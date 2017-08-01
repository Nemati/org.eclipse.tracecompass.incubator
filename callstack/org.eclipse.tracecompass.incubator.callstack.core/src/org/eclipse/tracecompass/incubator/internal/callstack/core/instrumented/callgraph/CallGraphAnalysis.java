/*******************************************************************************
 * Copyright (c) 2016 Ericsson
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.callstack.core.instrumented.callgraph;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.common.core.StreamUtils;
import org.eclipse.tracecompass.incubator.analysis.core.model.IHostModel;
import org.eclipse.tracecompass.incubator.analysis.core.model.ModelManager;
import org.eclipse.tracecompass.incubator.callstack.core.base.ICallStackElement;
import org.eclipse.tracecompass.incubator.callstack.core.base.ICallStackGroupDescriptor;
import org.eclipse.tracecompass.incubator.callstack.core.callgraph.AggregatedCallSite;
import org.eclipse.tracecompass.incubator.callstack.core.callgraph.CallGraphGroupBy;
import org.eclipse.tracecompass.incubator.callstack.core.callgraph.ICallGraphProvider;
import org.eclipse.tracecompass.incubator.callstack.core.flamechart.CallStack;
import org.eclipse.tracecompass.incubator.callstack.core.instrumented.ICalledFunction;
import org.eclipse.tracecompass.incubator.callstack.core.instrumented.IFlameChartProvider;
import org.eclipse.tracecompass.incubator.callstack.core.instrumented.statesystem.CallStackSeries;
import org.eclipse.tracecompass.incubator.internal.callstack.core.instrumented.InstrumentedCallStackElement;
import org.eclipse.tracecompass.segmentstore.core.ISegment;
import org.eclipse.tracecompass.segmentstore.core.ISegmentStore;
import org.eclipse.tracecompass.segmentstore.core.SegmentStoreFactory;
import org.eclipse.tracecompass.segmentstore.core.SegmentStoreFactory.SegmentStoreType;
import org.eclipse.tracecompass.tmf.core.analysis.IAnalysisModule;
import org.eclipse.tracecompass.tmf.core.analysis.TmfAbstractAnalysisModule;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Multimap;

/**
 * Call stack analysis used to create a segment for each call function from an
 * entry/exit event. It builds a segment tree from the state system. An example
 * taken from the Fibonacci trace's callStack shows the structure of the segment
 * tree given by this analysis:
 *
 * <pre>
 * (Caller)  main
 *            ↓↑
 * (Callee) Fibonacci
 *           ↓↑    ↓↑
 *      Fibonacci Fibonacci
 *         ↓↑         ↓↑
 *         ...        ...
 * </pre>
 *
 * @author Sonia Farrah
 */
public class CallGraphAnalysis extends TmfAbstractAnalysisModule implements ICallGraphProvider {

    /**
     * Public ID for this analysis
     */
    public static final String ID = "org.eclipse.tracecompass.incubator.callstack.callgraph"; //$NON-NLS-1$

    // ------------------------------------------------------------------------
    // Attributes
    // ------------------------------------------------------------------------

    /**
     * Segment store
     */
    private final ISegmentStore<@NonNull ISegment> fStore;

    /**
     * The Trace's root functions list
     */
    private final List<ICalledFunction> fRootFunctions = new ArrayList<>();
    private final IFlameChartProvider fCsProvider;

    /**
     * The List of thread nodes. Each thread has a virtual node having the root
     * function as children
     */
    private final Set<ICallStackElement> fRootElements = new HashSet<>();
    private final Multimap<ICallStackElement, AggregatedCallSite> fCcts = HashMultimap.create();

    private @Nullable ICallStackGroupDescriptor fGroupBy = null;

    private @Nullable Multimap<ICallStackElement, AggregatedCallSite> fGroupedCct = null;

    /**
     * Constructor
     *
     * @param csProvider
     *            The call stack provider to use with this analysis
     */
    public CallGraphAnalysis(IFlameChartProvider csProvider) {
        super();
        fStore = SegmentStoreFactory.createSegmentStore(SegmentStoreType.Fast);
        fCsProvider = csProvider;
    }

    @Override
    public @NonNull String getHelpText() {
        String msg = Messages.CallGraphAnalysis_Description;
        return (msg != null) ? msg : super.getHelpText();
    }

    @Override
    public @NonNull String getHelpText(@NonNull ITmfTrace trace) {
        return getHelpText();
    }

    @Override
    public boolean canExecute(ITmfTrace trace) {
        return true;
    }

    @Override
    protected Iterable<IAnalysisModule> getDependentAnalyses() {
        return Collections.singleton(fCsProvider);
    }

    @Override
    protected boolean executeAnalysis(@Nullable IProgressMonitor monitor) {
        ITmfTrace trace = getTrace();
        if (monitor == null || trace == null) {
            return false;
        }
        Iterable<IAnalysisModule> dependentAnalyses = getDependentAnalyses();
        for (IAnalysisModule module : dependentAnalyses) {
            if (!(module instanceof IFlameChartProvider)) {
                return false;
            }
            module.schedule();
        }
        // TODO:Look at updates while the state system's being built
        dependentAnalyses.forEach((t) -> t.waitForCompletion(monitor));

        for (IAnalysisModule module : dependentAnalyses) {
            IFlameChartProvider callstackModule = (IFlameChartProvider) module;
            IHostModel model = ModelManager.getModelFor(callstackModule.getHostId());

            for (CallStackSeries callstack : callstackModule.getCallStackSeries()) {
                if (!iterateOverCallstackSerie(callstack, model, monitor)) {
                    return false;
                }
            }
        }
        monitor.worked(1);
        monitor.done();
        return true;

    }

    // private ICallStackElement createGroups(ICallStackElement element,
    // IHostModel model, IProgressMonitor monitor) {
    // if (element instanceof ICallStackLeafElement) {
    // String name = element.getName();
    // LeafGroupNode leafGroup = new InstrumentedGroup(name,
    // element.getGroup());
    // iterateOverElement((ICallStackLeafElement) element, leafGroup, model,
    // monitor);
    // return leafGroup;
    // }
    // ICallStackElement group = new CallStackElement(element.getName(),
    // element.getGroup());
    // for (ICallStackElement child : element.getChildren()) {
    // group.addChild(createGroups(child, model, monitor));
    // }
    // return group;
    // }

    /**
     * Iterate over a callstack series. It will do a depth-first search to
     * create teh callgraph
     *
     * @param callstackSerie
     *            The series to iterate over
     * @param model
     *            The model of the host on which this callstack was running
     * @param monitor
     *            A progress monitor
     * @return Whether the series was successfully iterated over
     */
    @VisibleForTesting
    protected boolean iterateOverCallstackSerie(CallStackSeries callstackSerie, IHostModel model, IProgressMonitor monitor) {
        // The root elements are the same as the one from the callstack series
        Collection<ICallStackElement> rootElements = callstackSerie.getRootElements();
        fRootElements.addAll(rootElements);
        for (ICallStackElement element : rootElements) {
            if (monitor.isCanceled()) {
                return false;
            }
            iterateOverElement(element, model, monitor);
        }
        return true;
    }

    private void iterateOverElement(ICallStackElement element, IHostModel model, IProgressMonitor monitor) {
        // Iterator over the children of the element until we reach the leaves
        if (element.isLeaf()) {
            iterateOverRootElement(element, model, monitor);
            return;
        }
        for (ICallStackElement child : element.getChildren()) {
            iterateOverElement(child, model, monitor);
        }
    }

    private void iterateOverRootElement(ICallStackElement element, IHostModel model, IProgressMonitor monitor) {
        if (!(element instanceof InstrumentedCallStackElement)) {
            throw new IllegalStateException("Call Graph Analysis: The element does not have the right type"); //$NON-NLS-1$
        }
        InstrumentedCallStackElement insElement = (InstrumentedCallStackElement) element;
        CallStack callStack = insElement.getCallStack();

        // Create a root segment

        AbstractCalledFunction nextFunction = (AbstractCalledFunction) callStack.getNextFunction(callStack.getStartTime(), 1, null, model);
        while (nextFunction != null) {
            AggregatedCalledFunction aggregatedChild = createCallSite(nextFunction.getSymbol());
            iterateOverCallstack(callStack, nextFunction, 2, aggregatedChild, model, monitor);
            aggregatedChild.addFunctionCall(nextFunction);
            addAggregatedCallSite(element, aggregatedChild);
            fRootFunctions.add(nextFunction);
            nextFunction = (AbstractCalledFunction) callStack.getNextFunction(nextFunction.getEnd(), 1, null, model);
        }
    }

    private void iterateOverCallstack(CallStack callstack, ICalledFunction function, int nextLevel, AggregatedCalledFunction aggregatedCall, IHostModel model, IProgressMonitor monitor) {
        fStore.add(function);
        if (nextLevel > callstack.getMaxDepth()) {
            return;
        }

        AbstractCalledFunction nextFunction = (AbstractCalledFunction) callstack.getNextFunction(function.getStart(), nextLevel, function, model);
        while (nextFunction != null) {
            AggregatedCalledFunction aggregatedChild = createCallSite(nextFunction.getSymbol());
            iterateOverCallstack(callstack, nextFunction, nextLevel + 1, aggregatedChild, model, monitor);
            aggregatedCall.addChild(nextFunction, aggregatedChild);
            nextFunction = (AbstractCalledFunction) callstack.getNextFunction(nextFunction.getEnd(), nextLevel, function, model);
        }

    }

    /**
     * Get the callstack series of the providers of this analysis
     *
     * @return The collection of callstack series
     */
    public Collection<CallStackSeries> getSeries() {
        List<CallStackSeries> series = new ArrayList<>();
        for (IAnalysisModule dependent : getDependentAnalyses()) {
            if (!(dependent instanceof IFlameChartProvider)) {
                continue;
            }
            IFlameChartProvider csProvider = (IFlameChartProvider) dependent;
            series.addAll(csProvider.getCallStackSeries());
        }
        return series;
    }

    @Override
    protected void canceling() {
        // Do nothing
    }

    /**
     * The functions of the first level
     *
     * @return Functions of the first level
     */
    public List<ICalledFunction> getRootFunctions() {
        return ImmutableList.copyOf(fRootFunctions);
    }

    /**
     * Get the segment store that accompanies this callgraph
     *
     * FIXME: Is this analysis the right place for the segment store, or should
     * it be during call stack building
     *
     * @return The segment store
     */
    public ISegmentStore<ISegment> getSegmentStore() {
        return fStore;
    }

    /**
     * Set the group descriptor by which to group the callgraph data
     *
     * @param descriptor
     *            The descriptor by which to group the callgraph elements, or
     *            <code>null</code> will group them all together
     */
    @Override
    public void setGroupBy(@Nullable ICallStackGroupDescriptor descriptor) {
        fGroupBy = descriptor;
        fGroupedCct = null;
    }

    @Override
    public Collection<ICallStackElement> getElements() {
        ICallStackGroupDescriptor groupBy = fGroupBy;
        Collection<ICallStackElement> elements = fRootElements;
        if (groupBy == null) {
            return ImmutableList.copyOf(elements);
        }

        Multimap<ICallStackElement, AggregatedCallSite> groupedCct = fGroupedCct;
        if (groupedCct == null) {
            groupedCct = CallGraphGroupBy.groupCallGraphBy(groupBy, elements, this);
            fGroupedCct = groupedCct;
        }
        return groupedCct.keySet();
    }

    @Override
    public Collection<ICallStackGroupDescriptor> getGroupDescriptors() {
        return StreamUtils.getStream(getDependentAnalyses())
                .flatMap(m -> StreamUtils.getStream(((IFlameChartProvider) m).getCallStackSeries()))
                .map(CallStackSeries::getRootGroup)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<AggregatedCallSite> getCallingContextTree(ICallStackElement element) {
        Multimap<ICallStackElement, AggregatedCallSite> groupedCct = fGroupedCct;
        if (groupedCct != null) {
            return groupedCct.get(element);
        }
        return fCcts.get(element);
    }

    @Override
    public AggregatedCalledFunction createCallSite(Object symbol) {
        return new AggregatedCalledFunction(symbol);
    }

    @Override
    public void addAggregatedCallSite(ICallStackElement dstGroup, AggregatedCallSite callsite) {
        Collection<AggregatedCallSite> callsites = fCcts.get(dstGroup);
        for (AggregatedCallSite site : callsites) {
            if (site.getSymbol().equals(callsite.getSymbol())) {
                site.merge(callsite);
                return;
            }
        }
        fCcts.put(dstGroup, callsite);
    }

}