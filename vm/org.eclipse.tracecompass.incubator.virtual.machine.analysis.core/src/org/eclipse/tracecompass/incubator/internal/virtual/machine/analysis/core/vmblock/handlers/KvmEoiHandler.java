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
public class KvmEoiHandler extends VMblockAnalysisEventHandler {

    public KvmEoiHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

        super(layout, sp);

    }

    // @SuppressWarnings("null")
    @Override
    public void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event) {

        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }
        //final long ts = event.getTimestamp().getValue();
        ITmfEventField content = event.getContent();
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        //Long apicid = checkNotNull((Long)content.getField("apicid").getValue()); //$NON-NLS-1$
        Long vec = checkNotNull((Long)content.getField("vector").getValue()); //$NON-NLS-1$

        if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {
            Integer vcpu = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue());
            Integer lastExit = KvmEntryHandler.pid2VM.get(pid.intValue()).getLastExit(vcpu);
            if (lastExit.equals(1) || lastExit.equals(32)) {
                 if (vec.equals(238L)) {
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setLastExit(vcpu, 100);
                }
            } else if (lastExit.equals(100) && vec.equals(253L)) {
                KvmEntryHandler.pid2VM.get(pid.intValue()).setLastExit(vcpu, 12);
            }

        }



    }

}
