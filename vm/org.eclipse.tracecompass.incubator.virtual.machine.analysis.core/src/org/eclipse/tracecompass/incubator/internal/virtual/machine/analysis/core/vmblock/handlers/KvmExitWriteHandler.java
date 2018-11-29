/*******************************************************************************
 * Copyright (c) 2016 École Polytechnique de Montréal
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;

import static org.eclipse.tracecompass.common.core.NonNullUtils.checkNotNull;




import org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelAnalysisEventLayout;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;



/**
 * @author Hani Nemati
 */
public class KvmExitWriteHandler extends VMblockAnalysisEventHandler {

    public KvmExitWriteHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

        super(layout, sp);

    }

    // @SuppressWarnings("null")
    @Override
    public void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event) {

        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }
        final long ts = event.getTimestamp().getValue();
        ITmfEventField content = event.getContent();
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        Long ret = checkNotNull((Long)content.getField("ret").getValue()); //$NON-NLS-1$

        if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {
            Long begin = KvmEntryHandler.pid2VM.get(pid.intValue()).getWrite2Time(tid.intValue());
            KvmEntryHandler.pid2VM.get(pid.intValue()).setWrite2Time(tid.intValue(), 0L);
            KvmEntryHandler.pid2VM.get(pid.intValue()).addWriteLatency(pid.intValue(),ts-begin);
            KvmEntryHandler.pid2VM.get(pid.intValue()).addWrite2Block(pid.intValue(), ret);


            int quark = VMblockAnalysisUtils.getDiskWriteBlockQuark(ss, pid.intValue());
            Long blockWrite = KvmEntryHandler.pid2VM.get(pid.intValue()).getWrite2Block(pid.intValue());
            VMblockAnalysisUtils.setLong(ss, quark, ts, blockWrite);


            quark = VMblockAnalysisUtils.getDiskWriteLatencyQuark(ss, pid.intValue());
            Long writeLatency = KvmEntryHandler.pid2VM.get(pid.intValue()).getWriteLatency(pid.intValue());
            VMblockAnalysisUtils.setLong(ss, quark, ts, writeLatency);


            if (KvmEntryHandler.diskInternal.containsKey(pid.intValue())) {
                int diskUsage = KvmEntryHandler.diskInternal.get(pid.intValue());
                if (diskUsage==1) {
                    KvmEntryHandler.diskInternal.remove(pid.intValue());
                } else {
                    KvmEntryHandler.diskInternal.put(pid.intValue(), --diskUsage);
                }

            }
            KvmEntryHandler.diskUse--;

        }
    }

}
