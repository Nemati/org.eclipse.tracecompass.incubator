/*******************************************************************************
 * Copyright (c) 2017 École Polytechnique de Montréal
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;

import static org.eclipse.tracecompass.common.core.NonNullUtils.checkNotNull;


import org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelAnalysisEventLayout;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.module.StateValues;
//import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.module.StateValues;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;

/**
 * @author Hani Nemati
 */
public class SchedSwitchHandler extends VMblockAnalysisEventHandler {

    /**
     * Constructor
     *
     * @param layout
     *            The event layout of the trace being analyzed by this handler
     * @param sp
     *            The state provider
     */
    public SchedSwitchHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {
        super(layout, sp);
    }

    @Override
    public void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event) {
        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }

        ITmfEventField content = event.getContent();
        final long ts = event.getTimestamp().getValue();
        Long prevTid = checkNotNull((Long) content.getField(getLayout().fieldPrevTid()).getValue());
        Long nextTid = checkNotNull((Long) content.getField(getLayout().fieldNextTid()).getValue());
        String nextComm = checkNotNull( content.getField(getLayout().fieldNextComm()).getValue().toString());
        if (nextComm.contains("vhost")) {
           Integer vhost_pid = Integer.valueOf(nextComm.substring(6));
               KvmEntryHandler.net2VM.put(nextTid.intValue(), vhost_pid);
        }
        if (KvmEntryHandler.tid2pid.containsKey(nextTid.intValue())) {
            int pid = KvmEntryHandler.tid2pid.get(nextTid.intValue());
            int vCPU_ID = KvmEntryHandler.pid2VM.get(pid).getvcpu(nextTid.intValue());
            KvmEntryHandler.pid2VM.get(pid).setTsStart(vCPU_ID, ts);
        }
        if (KvmEntryHandler.tid2pid.containsKey(prevTid.intValue())) {

            Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$

            Integer vCPU_ID = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(prevTid.intValue());
            if (KvmEntryHandler.pid2VM.get(pid.intValue()).getVcpuReasonSet(vCPU_ID) == 0) {
                Long end = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsEnd(vCPU_ID);
                if (end != null) {
                    int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID);
                    int value = StateValues.VCPU_STATUS_UNKNOWN;
                    VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, end, value);
                    Long start = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID);
                    if (start != null) {
                        value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, start, value);
                        Long unknownWait = KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("unknown"); //$NON-NLS-1$
                        unknownWait +=start-end;
                        KvmEntryHandler.pid2VM.get(pid.intValue()).setWait("unknown", unknownWait); //$NON-NLS-1$
                        int waitQuark = VMblockAnalysisUtils.getUnknownQuark(ss, pid.intValue());
                        VMblockAnalysisUtils.setWait(ss, waitQuark, ts, unknownWait);
                    }
                }
            }
            KvmEntryHandler.pid2VM.get(pid.intValue()).setTsEnd(vCPU_ID, ts);
            //String cr3 = KvmEntryHandler.pid2VM.get(pid.intValue()).getCr3(vCPU_ID);
            KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2cr3(vCPU_ID, "0");

            KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpuReasonSet(vCPU_ID, 0);
            /*
            if (cr3 != null) {
                int value = StateValues.VCPU_STATUS_UNKNOWN;
                int quark = VMblockAnalysisUtils.getProcessCr3Quark(ss, pid.intValue(), cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, value);
            }
             */
            /*
            if (!KvmEntryHandler.pid2VM.get(pid.intValue()).getLastExit(vCPU_ID).equals(12)) {
                int value = StateValues.VCPU_STATUS_PREEMPTED_L0;
                int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, ts, value);

            }
             */

        }




    }





}
