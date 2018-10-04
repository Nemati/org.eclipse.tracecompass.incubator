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
public class KvmExitReadHandler extends VMblockAnalysisEventHandler {

    public KvmExitReadHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

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
            Long begin = KvmEntryHandler.pid2VM.get(pid.intValue()).getRead2Time(tid.intValue());
            KvmEntryHandler.pid2VM.get(pid.intValue()).setRead2Time(tid.intValue(),0L);
            if (begin>0L) {
                KvmEntryHandler.pid2VM.get(pid.intValue()).addReadLatency(pid.intValue(),ts-begin);
            }
            KvmEntryHandler.pid2VM.get(pid.intValue()).addRead2Block(pid.intValue(), ret);
           /*
            Long blockWrite = KvmEntryHandler.pid2VM.get(pid.intValue()).getWrite2Block(pid.intValue());
            Long blockRead = KvmEntryHandler.pid2VM.get(pid.intValue()).getRead2Block(pid.intValue());
            Long writeLatency = KvmEntryHandler.pid2VM.get(pid.intValue()).getWriteLatency(pid.intValue());
            Long readLatency = KvmEntryHandler.pid2VM.get(pid.intValue()).getReadLatency(pid.intValue());
            System.out.println("Write:"+blockWrite+"  Latency:"+writeLatency+"  Read:"+blockRead+"   Latency:"+readLatency);
            */
            int quark = VMblockAnalysisUtils.getDiskReadBlockQuark(ss, pid.intValue());
            Long blockRead = KvmEntryHandler.pid2VM.get(pid.intValue()).getRead2Block(pid.intValue());
            VMblockAnalysisUtils.setLong(ss, quark, ts, blockRead);
            quark = VMblockAnalysisUtils.getDiskReadLatencyQuark(ss, pid.intValue());
            Long readLatency = KvmEntryHandler.pid2VM.get(pid.intValue()).getReadLatency(pid.intValue());
            VMblockAnalysisUtils.setLong(ss, quark, ts, readLatency);
        }
    }

}
