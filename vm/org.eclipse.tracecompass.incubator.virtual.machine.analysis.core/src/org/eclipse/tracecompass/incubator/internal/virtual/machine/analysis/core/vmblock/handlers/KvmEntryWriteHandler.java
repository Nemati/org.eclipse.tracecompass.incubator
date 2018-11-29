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
public class KvmEntryWriteHandler extends VMblockAnalysisEventHandler {

    public KvmEntryWriteHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

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

        if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {
            KvmEntryHandler.pid2VM.get(pid.intValue()).setWrite2Time(tid.intValue(), ts);
            KvmEntryHandler.diskUse++;


            if (KvmEntryHandler.diskInternal.containsKey(pid.intValue())) {
                int diskUsage = KvmEntryHandler.diskInternal.get(pid.intValue());
                KvmEntryHandler.diskInternal.put(pid.intValue(), ++diskUsage);
            } else {
                KvmEntryHandler.diskInternal.put(pid.intValue(), 1);
            }

            if (KvmEntryHandler.diskUse>1) {


                for (Integer key : KvmEntryHandler.diskInternal.keySet()) {
                    if (key.equals(pid.intValue())) {
                        int quark = VMblockAnalysisUtils.getDiskInternal(ss, key);
                        VMblockAnalysisUtils.setDiskInternal(ss, quark, ts, 0);
                        VMblockAnalysisUtils.setDiskInternal(ss, quark, ts, KvmEntryHandler.diskInternal.get(key));
                    } else {
                        int quark = VMblockAnalysisUtils.getDiskExternal(ss, key);
                        VMblockAnalysisUtils.setDiskExternal(ss, quark, ts, 0);
                        VMblockAnalysisUtils.setDiskExternal(ss, quark, ts, KvmEntryHandler.diskInternal.get(key));
                    }
                }

                //int quark = VMblockAnalysisUtils.getDiskInternal(ss, pid.intValue());
                //VMblockAnalysisUtils.setDiskInternal(ss, quark, ts, KvmEntryHandler.diskUse);


            }

        }



    }

}
