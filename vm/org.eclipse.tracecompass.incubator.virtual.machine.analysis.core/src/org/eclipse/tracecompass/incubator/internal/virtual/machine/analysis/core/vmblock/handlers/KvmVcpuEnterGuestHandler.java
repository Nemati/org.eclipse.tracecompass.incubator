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
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.module.StateValues;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;



/**
 * @author Hani Nemati
 */
public class KvmVcpuEnterGuestHandler extends VMblockAnalysisEventHandler {

    public KvmVcpuEnterGuestHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

        super(layout, sp);

    }

    @SuppressWarnings("null")
    @Override
    public void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event) {

        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }

        ITmfEventField content = event.getContent();
        Long vCPU_ID = checkNotNull((Long)content.getField("vcpuID").getValue()); //$NON-NLS-1$
        String cr3 = checkNotNull(content.getField("cr3tmp").getValue().toString()); //$NON-NLS-1$
        String sp = Long.toUnsignedString(content.getFieldValue(Long.class, "sptmp"));
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$

        final long ts = event.getTimestamp().getValue();
        if (!KvmEntryHandler.tid2pid.containsKey(tid.intValue())) {
            KvmEntryHandler.tid2pid.put(tid.intValue(), pid.intValue());
        }

        if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {

            KvmEntryHandler.pid2VM.get(pid.intValue()).setTid2Vcpu(tid.intValue(), vCPU_ID.intValue());
            KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2cr3(vCPU_ID.intValue(), cr3);
            String lastCr3 = KvmEntryHandler.pid2VM.get(pid.intValue()).getCr3(vCPU_ID.intValue());

            if (lastCr3 == null) {
                // it is the first time
                KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2cr3(vCPU_ID.intValue(), cr3);
                int quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), cr3);
                int value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                quark = VMblockAnalysisUtils.getVcpuCr3Value(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, cr3);
                quark = VMblockAnalysisUtils.getVcpuSpValue(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, sp);
                quark = VMblockAnalysisUtils.getProcessCr3VcpuQuark(ss, pid.intValue(),cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vCPU_ID.intValue());

            }
            else if (lastCr3.equals("0")) { //$NON-NLS-1$
                // It is the first after scheduling
                KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2cr3(vCPU_ID.intValue(), cr3);
                int quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), cr3);
                int value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                quark = VMblockAnalysisUtils.getVcpuCr3Value(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, cr3);
                quark = VMblockAnalysisUtils.getVcpuSpValue(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, sp);
                quark = VMblockAnalysisUtils.getProcessCr3VcpuQuark(ss, pid.intValue(),cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vCPU_ID.intValue());
            }
            else if (lastCr3.equals(cr3)){
                // No change -- set the sp
                KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2sp(vCPU_ID.intValue(), sp);
                int quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), cr3);
                int value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                quark = VMblockAnalysisUtils.getVcpuCr3Value(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, cr3);
                quark = VMblockAnalysisUtils.getVcpuSpValue(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, sp);
                quark = VMblockAnalysisUtils.getProcessCr3VcpuQuark(ss, pid.intValue(),cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vCPU_ID.intValue());
            }
            else { //$NON-NLS-1$
                // if it is not null, so we had other Cr3 and now it is being preempted for last

                int quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), lastCr3);
                int value = StateValues.VCPU_STATUS_PREEMPTED_L1;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                quark = VMblockAnalysisUtils.getVcpuCr3Value(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, lastCr3);
                quark = VMblockAnalysisUtils.getVcpuSpValue(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, sp);
                quark = VMblockAnalysisUtils.getProcessCr3VcpuQuark(ss, pid.intValue(),lastCr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vCPU_ID.intValue());
            }
        } else {
            blockVMclass VMclass = new blockVMclass(pid.intValue(),tid.intValue(),vCPU_ID.intValue(), cr3);
            KvmEntryHandler.pid2VM.put(pid.intValue(),VMclass);
        }

    }

}
