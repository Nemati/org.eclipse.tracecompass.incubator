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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelAnalysisEventLayout;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;



/**
 * @author Hani Nemati
 */
public class KvmHyperCallHandler extends VMblockAnalysisEventHandler {
    public static Map<Integer,blockVMclass> pid2VM = new HashMap<>();
    public static Map<Integer,Integer> tid2pid = new HashMap<>();
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
        ITmfEventField content = event.getContent();
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        //Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        Long a0 = checkNotNull((Long)content.getField("a0").getValue()); //$NON-NLS-1$
        Long a2 = checkNotNull((Long)content.getField("a2").getValue()); //$NON-NLS-1$
        System.out.println(a0+a2+pid);
        /*
        Integer lttng_sessiond1 = 2144;
        Integer lttng_runas1 = 2145;
        Integer lttng_consumerd = 2212;
        Integer lttng_runas2 = 2214;
        */
        List<Long> listLttng = new ArrayList<>();
        /*listLttng.add(2144L);
        listLttng.add(2145L);
        listLttng.add(2212L);
        listLttng.add(2214L);
        */
        listLttng.add(19388L);



    }

}
