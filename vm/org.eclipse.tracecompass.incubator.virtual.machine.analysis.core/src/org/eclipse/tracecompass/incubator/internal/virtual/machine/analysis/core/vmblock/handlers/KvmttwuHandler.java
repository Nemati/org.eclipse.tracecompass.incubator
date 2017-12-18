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
public class KvmttwuHandler extends VMblockAnalysisEventHandler {

    public KvmttwuHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

        super(layout, sp);

    }

    @SuppressWarnings("null")
    @Override
    public void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event) {

        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }
        //final long ts = event.getTimestamp().getValue();
        ITmfEventField content = event.getContent();
        Long wtid =  checkNotNull((Long)content.getField("tid").getValue()); //$NON-NLS-1$
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$



        if ( KvmEntryHandler.pid2VM.containsKey(pid.intValue()) &&  KvmEntryHandler.tid2pid.containsKey(wtid.intValue()) ) {
            if (KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue())!=null && KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(wtid.intValue())!=null) {
                Integer vcpu_wakee = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(wtid.intValue());
                Integer vcpu_wakeup = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue());
                String lastCr3 = KvmEntryHandler.pid2VM.get(pid.intValue()).getCr3(vcpu_wakeup);
                KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2cr3Wakeup(vcpu_wakee, lastCr3);
            }
        }


    }

}
