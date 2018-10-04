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
 * For net_dev_xmit
 * For transmitting the packets
 */
public class KvmNetTXHandler extends VMblockAnalysisEventHandler {

    public KvmNetTXHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

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
        //Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        Long len = checkNotNull((Long)content.getField("len").getValue()); //$NON-NLS-1$
        String ifName = (String) checkNotNull(content.getField("name").getValue()); //$NON-NLS-1$
        Integer vhost_pid = KvmEntryHandler.net2VM.get(tid.intValue());

        if (KvmEntryHandler.pid2VM.containsKey(vhost_pid) && ifName.contains("vnet")) {
            Long trans =  KvmEntryHandler.pid2VM.get(vhost_pid).addNetTransmit(len);
            int quark = VMblockAnalysisUtils.getNetTransmitQuark(ss, vhost_pid);
            VMblockAnalysisUtils.setLong(ss, quark, ts, trans);
        }



    }

}