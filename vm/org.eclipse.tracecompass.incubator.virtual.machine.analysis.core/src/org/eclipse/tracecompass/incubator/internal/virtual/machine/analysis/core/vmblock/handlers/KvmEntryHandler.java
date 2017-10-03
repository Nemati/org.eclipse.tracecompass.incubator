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

import java.util.HashMap;
import java.util.Map;


import org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelAnalysisEventLayout;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.module.StateValues;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;



/**
 * @author Hani Nemati
 */
public class KvmEntryHandler extends VMblockAnalysisEventHandler {
    public static Map<Integer,blockVMclass> pid2VM = new HashMap<>();
    public static Map<Integer,Integer> net2VM = new HashMap<>();
    public static Map<Integer,Integer> tid2pid = new HashMap<>();
    public KvmEntryHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

        super(layout, sp);

    }

    @SuppressWarnings("null")
    @Override
    public void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event) {

        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }
        final long ts = event.getTimestamp().getValue();
        ITmfEventField content = event.getContent();
        Long vCPU_ID = checkNotNull((Long)content.getField("vcpu_id").getValue()); //$NON-NLS-1$
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$

        if (!tid2pid.containsKey(tid.intValue())) {
             tid2pid.put(tid.intValue(), pid.intValue());
        }

        if (pid2VM.containsKey(pid.intValue())) {

/*
            if (KvmEntryHandler.pid2VM.get(pid.intValue()).lttngOnVcpu) {

                /// for Abder /////////////////////////
                if (KvmEntryHandler.pid2VM.get(pid.intValue()).exitStart > 0L) {
                    Long diff = ts-KvmEntryHandler.pid2VM.get(pid.intValue()).exitStart;
                    int lastExit = KvmEntryHandler.pid2VM.get(pid.intValue()).getLastExit(vCPU_ID.intValue());
                    if (KvmEntryHandler.pid2VM.get(pid.intValue()).exitTime.containsKey(lastExit)) {
                        Long prevTime = KvmEntryHandler.pid2VM.get(pid.intValue()).exitTime.get(lastExit);
                        KvmEntryHandler.pid2VM.get(pid.intValue()).exitTime.put(lastExit, diff + prevTime);
                    } else {
                        KvmEntryHandler.pid2VM.get(pid.intValue()).exitTime.put(lastExit, diff);
                    }
                }
            }

            if (VMblockAnalysisUtils.formatTimeAbs(ts).equals("13:49:29.292175210")  ) {
                   System.out.println( KvmEntryHandler.pid2VM.get(pid.intValue()).exitTime.get(30));
                   Iterator it = KvmEntryHandler.pid2VM.get(pid.intValue()).exitTime.entrySet().iterator();
                   while (it.hasNext()) {
                       Map.Entry pair = (Map.Entry)it.next();
                       System.out.println(pair.getKey() + " = " + pair.getValue());
                       it.remove(); // avoids a ConcurrentModificationException
                   }
            }
            */
            //////////////////////////////////////////////////////////
           pid2VM.get(pid.intValue()).setTid2Vcpu(tid.intValue(), vCPU_ID.intValue());
        } else {
            blockVMclass VMclass = new blockVMclass(pid.intValue(),tid.intValue(),vCPU_ID.intValue());
            pid2VM.put(pid.intValue(),VMclass);
        }
        int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID.intValue());
        int value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, ts, value);


    }

}
