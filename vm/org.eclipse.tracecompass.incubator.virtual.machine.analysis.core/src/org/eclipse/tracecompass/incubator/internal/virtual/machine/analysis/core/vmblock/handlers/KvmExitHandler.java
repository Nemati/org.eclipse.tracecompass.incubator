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
public class KvmExitHandler extends VMblockAnalysisEventHandler {

    public KvmExitHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {
        super(layout, sp);
    }

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
        Long exit_reason = checkNotNull((Long)content.getField("exit_reason").getValue()); //$NON-NLS-1$

        if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {

            Integer vCPU_ID = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue());
            KvmEntryHandler.pid2VM.get(pid.intValue()).setLastExit(vCPU_ID, exit_reason.intValue());
            int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID);
            int value = StateValues.VCPU_STATUS_RUNNING_ROOT;
            VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, ts, value);
            int lastExitQuark = VMblockAnalysisUtils.getLastExitQuark(ss, pid.intValue(), vCPU_ID);
            VMblockAnalysisUtils.setLastExit(ss, lastExitQuark, ts, exit_reason.intValue());
            @SuppressWarnings("null")
            String cr3 = KvmEntryHandler.pid2VM.get(pid.intValue()).getCr3(vCPU_ID);

            if (cr3 != null ) {
                int quark = VMblockAnalysisUtils.getProcessCr3StatusQuark(ss, pid.intValue(), cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, value);
            }

        }




    }

}
