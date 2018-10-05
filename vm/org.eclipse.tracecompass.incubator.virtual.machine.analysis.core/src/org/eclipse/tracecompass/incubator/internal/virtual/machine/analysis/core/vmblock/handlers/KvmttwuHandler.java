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
        final long ts = event.getTimestamp().getValue();
        ITmfEventField content = event.getContent();
        //wtid is the tid of wakeup
        Long wtid =  checkNotNull((Long)content.getField("tid").getValue()); //$NON-NLS-1$
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$



        if ( KvmEntryHandler.pid2VM.containsKey(pid.intValue()) &&  KvmEntryHandler.tid2pid.containsKey(wtid.intValue()) ) {
            if (KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue())!=null && KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(wtid.intValue())!=null) {
                Integer vcpu_wakee = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(wtid.intValue());
                Integer vcpu_wakeup = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue());
                String lastCr3 = KvmEntryHandler.pid2VM.get(pid.intValue()).getCr3(vcpu_wakeup);
                KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2cr3Wakeup(vcpu_wakee, lastCr3);
                KvmEntryHandler.pid2VM.get(pid.intValue()).setNetworkWakeUp(0);
            }
        }
        // It means that the packet is comming from another VM
        if (KvmEntryHandler.net2VM.containsKey(tid.intValue()) && KvmEntryHandler.net2VM.containsKey(wtid.intValue())) {
            Integer vmWakeePid = KvmEntryHandler.net2VM.get(tid.intValue());
            Integer vmUpPid = KvmEntryHandler.net2VM.get(wtid.intValue());
            //wtid is the tid of waked up VM

            System.out.println(vmWakeePid + "--->" + vmUpPid);
            //Long rec = KvmEntryHandler.pid2VM.get(vhost_pid).addNetReceive(len);
            int quark = VMblockAnalysisUtils.getNetSendVMQuark(ss, vmWakeePid);
            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, 0);
            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, vmUpPid);
            //set who wakes this vm up
            KvmEntryHandler.pid2VM.get(vmWakeePid).setNetworkWakeUp(vmUpPid);
            // to find the vcpu that is being wakedup we should go for next wake up
        }



    }

}
