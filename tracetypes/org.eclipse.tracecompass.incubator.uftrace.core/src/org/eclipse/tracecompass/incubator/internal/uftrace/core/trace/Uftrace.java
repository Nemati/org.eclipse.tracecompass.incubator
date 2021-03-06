/*******************************************************************************
 * Copyright (c) 2017 Ericsson
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.uftrace.core.trace;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.incubator.internal.uftrace.core.Activator;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventType;
import org.eclipse.tracecompass.tmf.core.event.aspect.ITmfEventAspect;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfBaseAspects;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfTraceException;
import org.eclipse.tracecompass.tmf.core.symbols.ISymbolProvider;
import org.eclipse.tracecompass.tmf.core.symbols.ISymbolProviderFactory;
import org.eclipse.tracecompass.tmf.core.symbols.TmfResolvedSymbol;
import org.eclipse.tracecompass.tmf.core.trace.ITmfContext;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTraceKnownSize;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTraceWithPreDefinedEvents;
import org.eclipse.tracecompass.tmf.core.trace.TmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TraceValidationStatus;
import org.eclipse.tracecompass.tmf.core.trace.location.ITmfLocation;
import org.eclipse.tracecompass.tmf.core.trace.location.TmfLongLocation;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;

/**
 * Trace with the following data
 * <ul>
 * <li>info : various information about uftrace and running process</li>
 * <li>task.txt : task and session information</li>
 * <li>sid-<SESSION_ID>.map : memory mapping for a session</li>
 * <li>[PROGRAM].sym : (function) symbol address and name</li>
 * <li>[TID].dat : trace data for each task of given <TID></li>
 * <li>kernel_header : kernel ftrace header info (only if kernel tracing was
 * used)</li>
 * <li>kallsyms : kernel symbol information (ditto)</li>
 * <li>kernel-cpuX.dat : per-cpu kernel tracing data (ditto)</li>
 * </ul>
 *
 * @author Matthew Khouzam
 */
public class Uftrace extends TmfTrace implements ITmfTraceKnownSize, ITmfTraceWithPreDefinedEvents {

    private Collection<DatParser> fDats = new ArrayList<>();
    private MapParser fMap;
    private Map<String, SymParser> fSyms = new HashMap<>();
    private TaskParser fTasks;
    private TmfLongLocation fCurrentLoc = new TmfLongLocation(0L);

    private long fSize;

    private final ISymbolProvider fSymbolProvider = new UfTraceSymbolProvider();

    @Override
    public Iterable<ITmfEventAspect<?>> getEventAspects() {
        return ImmutableList.of(TmfBaseAspects.getTimestampAspect(), TmfBaseAspects.getEventTypeAspect(),
                new ITmfEventAspect<Integer>() {

                    @Override
                    public String getName() {
                        return "depth"; //$NON-NLS-1$
                    }

                    @Override
                    public String getHelpText() {
                        return ""; //$NON-NLS-1$
                    }

                    @Override
                    public @Nullable Integer resolve(ITmfEvent event) {
                        DatEvent fieldValue = (DatEvent) event.getContent().getValue();
                        return fieldValue.getDepth();
                    }
                }, new ITmfEventAspect<String>() {

                    @Override
                    public String getName() {
                        return "Address"; //$NON-NLS-1$
                    }

                    @Override
                    public String getHelpText() {
                        return ""; //$NON-NLS-1$
                    }

                    @Override
                    public @Nullable String resolve(ITmfEvent event) {
                        if (event.getContent().getValue() instanceof DatEvent) {
                            DatEvent datEvent = (DatEvent) event.getContent().getValue();
                            TmfResolvedSymbol symbol = fSymbolProvider.getSymbol(datEvent.getTid(), 0, datEvent.getAddress());
                            if (symbol != null) {
                                return symbol.getSymbolName();
                            }
                        }
                        return null;
                    }
                }

        );
    }

    @Override
    public IStatus validate(IProject project, String path) {
        File dir = new File(path);
        int confidence = 0;
        if (dir.isDirectory()) {
            confidence += 5;
            List<String> data = Arrays.asList(dir.list());
            for (String file : data) {
                if (file.endsWith(".dat")) { //$NON-NLS-1$
                    confidence += 4;
                }
                if (file.endsWith(".map")) { //$NON-NLS-1$
                    confidence += 4;
                }
                if (file.endsWith("*.sym")) { //$NON-NLS-1$
                    confidence += 3;
                }
            }
        }
        if (confidence > 10) {
            return new TraceValidationStatus(confidence, Activator.class.getCanonicalName());
        }
        return new Status(IStatus.ERROR, Activator.PLUGIN_ID, "Most probably not a UFTrace"); //$NON-NLS-1$
    }

    @Override
    public void initTrace(IResource resource, String path, Class<? extends ITmfEvent> type) throws TmfTraceException {
        File dir = new File(path);
        if (!dir.isDirectory()) {
            throw new TmfTraceException("trace is not a directory"); //$NON-NLS-1$
        }
        super.initTrace(resource, path, type);
        for (File child : dir.listFiles()) {
            String name = child.getName();
            try {
                if (name.endsWith(".dat")) { //$NON-NLS-1$
                    fSize += child.length();
                    fDats.add(new DatParser(child));
                } else if (name.endsWith(".map")) { //$NON-NLS-1$
                    fMap = MapParser.create(child);
                } else if (name.endsWith(".sym")) { //$NON-NLS-1$
                    fSyms.put(name.substring(0, name.length() - 4), SymParser.parse(child));
                } else if (name.equals("task.txt")) { //$NON-NLS-1$
                    fTasks = new TaskParser(child);
                }
            } catch (IOException e) {
                throw new TmfTraceException(e.getMessage(), e);
            }
        }
    }

    @Override
    public ITmfLocation getCurrentLocation() {
        return fCurrentLoc;
    }

    @Override
    public double getLocationRatio(ITmfLocation location) {
        return (long) location.getLocationInfo() / fSize;
    }

    @Override
    public ITmfContext seekEvent(ITmfLocation location) {
        UfContext context = new UfContext(fDats, this);
        if (location == null) {
            return context;
        }
        if (location instanceof TmfLongLocation) {
            TmfLongLocation longLocation = (TmfLongLocation) location;
            if (longLocation.getLocationInfo().longValue() == 0) {
                return context;
            }
            while (context.getLocation() != null && Long.compare(longLocation.getLocationInfo(), Objects.requireNonNull(context.getLocation()).getLocationInfo()) >= 0) {
                ITmfEvent next = context.getNext();
                if (next == null) {
                    break;
                }
                updateAttributes(context, next);
                if (context.getLocation() == null) {
                    return context;
                }
            }
        }
        return context;
    }

    @Override
    public ITmfContext seekEvent(double ratio) {
        return seekEvent(new TmfLongLocation((long) (ratio * fSize)));
    }

    @Override
    public ITmfEvent parseEvent(@Nullable ITmfContext ctx) {
        ITmfContext context = ctx;
        if (context == null) {
            context = seekEvent(0);
        }
        if (ctx instanceof UfContext) {
            UfContext ufContext = (UfContext) ctx;
            ITmfEvent tmfEvent = ufContext.getNext();
            if (tmfEvent != null) {
                fCurrentLoc = new TmfLongLocation(fCurrentLoc.getLocationInfo() + Long.BYTES * 2);
                ctx.setLocation(fCurrentLoc);
                updateAttributes(context, tmfEvent);
                return tmfEvent;
            }
        }
        return null;
    }

    @Override
    public Set<@NonNull ? extends ITmfEventType> getContainedEventTypes() {
        return UfEventType.TYPES;
    }

    @Override
    public int size() {
        return (int) (fSize / 1024);
    }

    @Override
    public int progress() {
        return (int) (fCurrentLoc.getLocationInfo() / 1024);
    }

    /**
     * Get the symbol provider for this trace
     *
     * @return the symbol provider
     */
    public ISymbolProvider getSymbolProvider() {
        return fSymbolProvider;
    }

    /**
     * Alleged symbol provider factory
     *
     * @author Matthew Khouzam
     *
     */
    public static class UfTraceSymbolProviderAllegedFactory implements ISymbolProviderFactory {

        @Override
        public @Nullable ISymbolProvider createProvider(@NonNull ITmfTrace trace) {
            if (trace instanceof Uftrace) {
                return ((Uftrace) trace).getSymbolProvider();
            }
            return null;
        }
    }

    /**
     * get the tasks parser
     *
     * @return The tasks parser
     */
    public TaskParser getTasks() {
        return fTasks;
    }

    /**
     * overly complicated, should clean up
     *
     * @author Matthew Khouzam
     *
     */
    private class UfTraceSymbolProvider implements ISymbolProvider {
        @Override
        public TmfResolvedSymbol getSymbol(int tid, long timestamp, long address) {
            String execName = fTasks.getExecName(tid);
            if (execName == null) {
                return new TmfResolvedSymbol(address, "0x" + Long.toHexString(address)); //$NON-NLS-1$
            }
            Entry<Long, MapEntry> key = fMap.getData().floorEntry(address);
            if (key == null) {
                return new TmfResolvedSymbol(address, "0x" + Long.toHexString(address)); //$NON-NLS-1$
            }
            long offset = address - key.getValue().getAddrLow();
            String pathName = key.getValue().getPathName();
            String substring = pathName.substring(pathName.lastIndexOf(File.separator) + 1);
            SymParser sym = fSyms.get(substring);
            if (sym == null) {
                return new TmfResolvedSymbol(address, "0x" + Long.toHexString(address)); //$NON-NLS-1$
            }
            String name = String.valueOf(sym.getMap().floorEntry(offset).getValue().getName());
            return new TmfResolvedSymbol(address, name);
        }

        @Deprecated
        @Override
        public @Nullable String getSymbolText(int pid, long timestamp, long address) {
            TmfResolvedSymbol symbol = getSymbol(pid, timestamp, address);
            if (symbol != null) {
                return symbol.getSymbolName();
            }
            return ""; //$NON-NLS-1$
        }

        /* needed for ISymbolProvider */
        @Override
        public @NonNull ITmfTrace getTrace() {
            return (ITmfTrace) this;
        }

        @Override
        public void loadConfiguration(@Nullable IProgressMonitor monitor) {
            // do nothing
        }

        @Deprecated
        @Override
        public @Nullable String getSymbolText(long address) {
            if (fTasks.getTids().size() == 1) {
                TmfResolvedSymbol symbol = getSymbol(Iterables.getFirst(fTasks.getTids(), -1), 0, address);
                if (symbol != null) {
                    return symbol.getSymbolName();
                }
            }
            return ""; //$NON-NLS-1$
        }

    }
}
