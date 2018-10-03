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
public class KvmHyperCallHandler extends VMblockAnalysisEventHandler {

    public KvmHyperCallHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

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
        Long nr = checkNotNull((Long)content.getField("nr").getValue()); //$NON-NLS-1$
        Long a0 = checkNotNull((Long)content.getField("a0").getValue()); //$NON-NLS-1$
        if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {

            Integer vCPU_ID = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue());
            int syscallQuark = VMblockAnalysisUtils.getHypercallStatus(ss, pid.intValue(), vCPU_ID);
            int syscallQuarkName = VMblockAnalysisUtils.getHypercallName(ss, pid.intValue(), vCPU_ID);
            if (nr.equals(1100L)) {

                int value = StateValues.SYSCALL;
                VMblockAnalysisUtils.setvCPUStatus(ss, syscallQuark, ts, value);
                String syscallName = KvmEntryHandler.sysNumber2Name.get(a0.toString());
                VMblockAnalysisUtils.setSyscallName(ss, syscallQuarkName, ts, syscallName);

            } else if ( nr.equals(1101L)) {

                int value = StateValues.USERSPACE;
                VMblockAnalysisUtils.setvCPUStatus(ss, syscallQuark, ts, value);

                VMblockAnalysisUtils.setSyscallName(ss, syscallQuarkName, ts, "");

            }
        }



    }

}