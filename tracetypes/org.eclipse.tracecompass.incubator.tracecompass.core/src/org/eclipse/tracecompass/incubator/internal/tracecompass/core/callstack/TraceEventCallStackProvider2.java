/*******************************************************************************
 * Copyright (c) 2017 Ericsson
 *
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.tracecompass.core.callstack;

import static org.eclipse.tracecompass.common.core.NonNullUtils.checkNotNull;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.analysis.os.linux.core.event.aspect.LinuxTidAspect;
import org.eclipse.tracecompass.analysis.os.linux.core.model.HostThread;
import org.eclipse.tracecompass.incubator.analysis.core.model.IHostModel;
import org.eclipse.tracecompass.incubator.callstack.core.instrumented.statesystem.CallStackEdge;
import org.eclipse.tracecompass.incubator.callstack.core.instrumented.statesystem.CallStackStateProvider;
import org.eclipse.tracecompass.incubator.callstack.core.instrumented.statesystem.InstrumentedCallStackAnalysis;
import org.eclipse.tracecompass.segmentstore.core.ISegmentStore;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.statesystem.core.statevalue.ITmfStateValue;
import org.eclipse.tracecompass.statesystem.core.statevalue.TmfStateValue;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.timestamp.ITmfTimestamp;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;

/**
 * Trace event callstack provider
 *
 * Has links, so we have a tmfGraph.
 *
 * @author Matthew Khouzam
 *
 */
public class TraceEventCallStackProvider2 extends CallStackStateProvider {

    /**
     * Link builder between events
     *
     * @author Matthew Khouzam
     */
    private final class EdgeBuilder {

        private @NonNull String fSrc = StringUtils.EMPTY;
        private @NonNull String fDst = StringUtils.EMPTY;
        private long fSrcTime = Long.MAX_VALUE;
        private int fSrcTid = IHostModel.UNKNOWN_TID;
        private int fDstTid = IHostModel.UNKNOWN_TID;
        private long fDur = 0;

        public long getTime() {
            return fSrcTime;
        }

        public @NonNull CallStackEdge build() {
            return new CallStackEdge(new HostThread(fSrc, fSrcTid), new HostThread(fDst, fDstTid), fSrcTime, fDur);
        }

    }

    private ITmfTimestamp fSafeTime;

    private final Map<String, EdgeBuilder> fLinks = new HashMap<>();

    /**
     * A map of tid/stacks of timestamps
     */
    private final Map<Integer, Deque<Long>> fStack = new TreeMap<>();

    private final ISegmentStore<@NonNull CallStackEdge> fLinksStore;

    /**
     * Constructor
     *
     * @param trace
     *            the trace to follow
     * @param segStore
     *            Segment store to populate
     */
    public TraceEventCallStackProvider2(@NonNull ITmfTrace trace, ISegmentStore<@NonNull CallStackEdge> segStore) {
        super(trace);
        ITmfStateSystemBuilder stateSystemBuilder = getStateSystemBuilder();
        if (stateSystemBuilder != null) {
            int quark = stateSystemBuilder.getQuarkAbsoluteAndAdd("dummy entry to make gpu entries work"); //$NON-NLS-1$
            stateSystemBuilder.modifyAttribute(0, TmfStateValue.newValueInt(0), quark);
        }
        fLinksStore = segStore;
        fSafeTime = trace.getStartTime();
    }

    @Override
    protected @Nullable String getProcessName(@NonNull ITmfEvent event) {
        String pName = event.getContent().getFieldValue(String.class, "pid"); //$NON-NLS-1$

        if (pName == null) {
            int processId = getProcessId(event);
            pName = (processId == UNKNOWN_PID) ? UNKNOWN : Integer.toString(processId);
        }

        return pName;
    }

    @Override
    protected int getProcessId(@NonNull ITmfEvent event) {
        Integer fieldValue = event.getContent().getFieldValue(Integer.class,"pid");
        return fieldValue == null ? -1 : fieldValue.intValue();
    }

    @Override
    protected long getThreadId(@NonNull ITmfEvent event) {
        Integer tid = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), LinuxTidAspect.class, event);
        if (tid == null) {
            return IHostModel.UNKNOWN_TID;
        }
        return tid;
    }

    @Override
    public int getVersion() {
        return 1;
    }

    @Override
    public @NonNull CallStackStateProvider getNewInstance() {
        return new TraceEventCallStackProvider2(getTrace(), fLinksStore);
    }

    @Override
    protected @Nullable ITmfStateValue functionEntry(@NonNull ITmfEvent event) {
        if (isEntry(event)) {
            return TmfStateValue.newValueString(event.getName());
        }
        return null;
    }

    private static boolean isEntry(ITmfEvent event) {
        String phase = event.getContent().getFieldValue(String.class, "ph");
        return "B".equals(phase) || "s".equals(phase);
    }

    @Override
    protected @Nullable ITmfStateValue functionExit(@NonNull ITmfEvent event) {
        if (isExit(event)) {
            return TmfStateValue.newValueString(event.getName());
        }
        return null;
    }

    private static boolean isExit(ITmfEvent event) {
        String phase = event.getContent().getFieldValue(String.class, "ph");
        return "E".equals(phase) || "f".equals(phase);
    }

    @Override
    protected void eventHandle(ITmfEvent event) {
//        if (!considerEvent(event)) {
//            return;
//        }
        ITmfStateSystemBuilder ss = Objects.requireNonNull(getStateSystemBuilder());

        /* Check if the event is a function entry */
        long timestamp = event.getTimestamp().toNanos();
        updateCloseCandidates(ss, timestamp);
        String processName = getProcessName(event);
        String ph = event.getContent().getFieldValue(String.class, "ph");
        if (ph == null) {
            return;
        }
        switch (ph) {
        case "B":
            handleStart(event, ss, timestamp, processName);
            break;

        case "s":
            handleStart(event, ss, timestamp, processName);
            updateSLinks(event);
            break;

        case "X":
            Long duration = event.getContent().getFieldValue(Long.class, "dur");
            if (duration != null) {
                handleComplete(event, ss, processName);
            }
            break;

        case "E":
            handleEnd(event, ss, timestamp, processName);
            break;

        case "f":
            handleEnd(event, ss, timestamp, processName);
            updateFLinks(event);
            break;

        case "b":
            handleStart(event, ss, timestamp, processName);
            break;

        // $CASES-OMITTED$
        default:
            return;
        }
    }

    private void updateCloseCandidates(ITmfStateSystemBuilder ss, long timestamp) {
        for (Entry<Integer, Deque<Long>> stackEntry : fStack.entrySet()) {
            Deque<Long> stack = stackEntry.getValue();
            if (!stack.isEmpty()) {
                Long closeCandidate = stack.pop();
                while (closeCandidate != null && closeCandidate < timestamp) {
                    ss.popAttribute(closeCandidate, stackEntry.getKey());
                    closeCandidate = (stack.isEmpty()) ? null : stack.pop();
                }
                if (closeCandidate != null) {
                    stack.push(closeCandidate);
                }
            }
        }
    }

    private void updateFLinks(ITmfEvent traceEvent) {
        String fId = traceEvent.getContent().getFieldValue(String.class, "id");
        EdgeBuilder fLink = fLinks.get(fId);
        if (fLink != null && fLink.getTime() == Long.MAX_VALUE) {
            fLink.fSrcTime = traceEvent.getTimestamp().toNanos();
        }
    }

    private void updateSLinks(ITmfEvent traceEvent) {
        String sId = traceEvent.getContent().getFieldValue(String.class, "id");
        EdgeBuilder sLink = fLinks.get(sId);
        long longTid = getThreadId(traceEvent);
        int tid = Long.valueOf(longTid).intValue();
        if (sLink != null) {
            if (sLink.getTime() == Long.MAX_VALUE) {
                sLink.fDur = 0;
                sLink.fSrcTime = traceEvent.getTimestamp().toNanos();
                sLink.fDstTid = tid;
                sLink.fDst = traceEvent.getTrace().getHostId();

                fLinksStore.add(sLink.build());
                EdgeBuilder builder = new EdgeBuilder();
                builder.fSrcTid = tid;
                builder.fSrc = traceEvent.getTrace().getHostId();
                fLinks.put(sId, builder);
            } else {
                /*
                 * start time = time
                 *
                 * end time = traceEvent.getTimestamp().toNanos()
                 */
                sLink.fDur = traceEvent.getTimestamp().toNanos() - sLink.fSrcTime;
                sLink.fDstTid = tid;
                sLink.fDst = traceEvent.getTrace().getHostId();

                fLinksStore.add(sLink.build());
                EdgeBuilder builder = new EdgeBuilder();
                builder.fSrcTime = traceEvent.getTimestamp().toNanos();
                builder.fSrcTid = tid;
                builder.fSrc = traceEvent.getTrace().getHostId();

                fLinks.put(sId, builder);
            }
        } else {
            EdgeBuilder builder = new EdgeBuilder();
            builder.fSrcTime = traceEvent.getTimestamp().toNanos();
            builder.fSrcTid = tid;
            builder.fSrc = traceEvent.getTrace().getHostId();
            fLinks.put(sId, builder);
        }
    }

    private int handleStart(@NonNull ITmfEvent event, ITmfStateSystemBuilder ss, long timestamp, String processName) {
        ITmfStateValue functionBeginName = functionEntry(event);
        if (functionBeginName != null) {
            int processQuark = ss.getQuarkAbsoluteAndAdd(PROCESSES, processName);

            String threadName = getThreadName(event);
            long threadId = getThreadId(event);
            if (threadName == null) {
                threadName = Long.toString(threadId);
            }
            int threadQuark = ss.getQuarkRelativeAndAdd(processQuark, threadName);

            int callStackQuark = ss.getQuarkRelativeAndAdd(threadQuark, InstrumentedCallStackAnalysis.CALL_STACK);
            ITmfStateValue value = functionBeginName;
            ss.pushAttribute(timestamp, value, callStackQuark);
            /*
             * FIXME: BIG FAT SMELLY HACK
             *
             * We are regenerating a stack without going through the helpers
             */
            return ss.queryOngoingState(callStackQuark).unboxInt() + callStackQuark;
        }
        return -1;
    }

    private int handleEnd(@NonNull ITmfEvent event, ITmfStateSystemBuilder ss, long timestamp, String processName) {
        /* Check if the event is a function exit */
        ITmfStateValue functionExitState = functionExit(event);
        if (functionExitState != null) {
            String pName = processName;

            if (pName == null) {
                int processId = getProcessId(event);
                pName = (processId == UNKNOWN_PID) ? UNKNOWN : Integer.toString(processId);
            }
            String threadName = getThreadName(event);
            if (threadName == null) {
                threadName = Long.toString(getThreadId(event));
            }
            int quark = ss.getQuarkAbsoluteAndAdd(PROCESSES, pName, threadName, InstrumentedCallStackAnalysis.CALL_STACK);
            ss.popAttribute(timestamp - 1, quark);
            /*
             * FIXME: BIG FAT SMELLY HACK
             *
             * We are regenerating a stack without going through the helpers
             */
            return ss.queryOngoingState(quark).unboxInt() + quark;
        }
        return -1;
    }

    /**
     * This handles phase "complete" elements. They arrive by end time first, some
     * some flipping is being performed.
     *
     * @param event
     * @param ss
     * @param processName
     */
    private void handleComplete(ITmfEvent event, ITmfStateSystemBuilder ss, String processName) {

        ITmfTimestamp timestamp = event.getTimestamp();
        fSafeTime = fSafeTime.compareTo(timestamp) > 0 ? fSafeTime : timestamp;
        String currentProcessName = processName;
        if (currentProcessName == null) {
            int processId = getProcessId(event);
            currentProcessName = (processId == UNKNOWN_PID) ? UNKNOWN : Integer.toString(processId).intern();
        }
        int processQuark = ss.getQuarkAbsoluteAndAdd(PROCESSES, currentProcessName);
        long startTime = event.getTimestamp().toNanos();
        long end = startTime;
        Long duration = event.getContent().getFieldValue(Long.class, "dur");
        if (duration != null) {
            end += Math.max(duration - 1, 0);
        }
        String threadName = getThreadName(event);
        long threadId = getThreadId(event);
        if (threadName == null) {
            threadName = Long.toString(threadId).intern();
        }
        int threadQuark = ss.getQuarkRelativeAndAdd(processQuark, threadName);

        int callStackQuark = ss.getQuarkRelativeAndAdd(threadQuark, InstrumentedCallStackAnalysis.CALL_STACK);
        ITmfStateValue functionEntry = TmfStateValue.newValueString(event.getName());
        ss.pushAttribute(startTime, functionEntry, callStackQuark);
        Deque<Long> stack = fStack.get(callStackQuark);
        if (stack == null) {
            stack = new ArrayDeque<>();
            fStack.put(callStackQuark, stack);
        }
        stack.push(end);

    }

    @Override
    public void done() {
        ITmfStateSystemBuilder ss = checkNotNull(getStateSystemBuilder());
        for (Entry<Integer, Deque<Long>> stackEntry : fStack.entrySet()) {
            Deque<Long> stack = stackEntry.getValue();
            if (!stack.isEmpty()) {
                Long closeCandidate = stack.pop();
                while (closeCandidate != null) {
                    ss.popAttribute(closeCandidate, stackEntry.getKey());
                    closeCandidate = (stack.isEmpty()) ? null : stack.pop();
                }
            }
        }
        fLinksStore.close(false);
        super.done();
    }

    @Override
    protected boolean considerEvent(@NonNull ITmfEvent event) {
        return true;
    }
}
