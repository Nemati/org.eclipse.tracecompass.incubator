/*******************************************************************************
 * Copyright (c) 2017 École Polytechnique de Montréal
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.graph;

import org.eclipse.tracecompass.analysis.graph.core.building.ITraceEventHandler;
import org.eclipse.tracecompass.analysis.os.linux.core.model.HostThread;
import org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelAnalysisEventLayout;
import org.eclipse.tracecompass.internal.lttng2.kernel.core.analysis.graph.model.EventField;
import org.eclipse.tracecompass.internal.lttng2.kernel.core.analysis.graph.model.LttngSystemModel;
import org.eclipse.tracecompass.internal.lttng2.kernel.core.analysis.graph.model.LttngWorker;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;

/**
 * A graph handler to handle kvm events and add proper links to the graph
 *
 * @author Geneviève Bastien
 */
public class KvmGraphHandler implements ITraceEventHandler {

    //private static final String KVM_INJ_VIRQ = "kvm_inj_virq"; //$NON-NLS-1$
    private final VirtualMachineExecGraphProvider fProvider;


    /**
     * Constructor
     *
     * @param provider
     *            The graph provider
     */
    public KvmGraphHandler(VirtualMachineExecGraphProvider provider) {
        fProvider = provider;
    }

    @SuppressWarnings("restriction")
    @Override
    public void handleEvent(ITmfEvent event) {
        String eventName = event.getName();
        IKernelAnalysisEventLayout eventLayout = fProvider.getEventLayout(event.getTrace());
        if (eventName.equals(eventLayout.eventSchedSwitch())) {
            handleSchedSwitch(event);
        }


    }
    @SuppressWarnings("restriction")
    private void handleSchedSwitch(ITmfEvent event) {

        String host = event.getTrace().getHostId();
//        long ts = event.getTimestamp().getValue();
        IKernelAnalysisEventLayout eventLayout = fProvider.getEventLayout(event.getTrace());
        String nextComm = EventField.getString(event, eventLayout.fieldNextComm());
        if (nextComm.equals("qemu-system-x86")) { //$NON-NLS-1$


            LttngSystemModel system = fProvider.getSystem();

            Integer next = EventField.getInt(event, eventLayout.fieldNextTid());

            System.out.println(nextComm+":"+ next);
            Integer prev = EventField.getInt(event, eventLayout.fieldPrevTid());

            LttngWorker nextTask = system.findWorker(new HostThread(host, next));
            LttngWorker prevTask = system.findWorker(new HostThread(host, prev));

            if (prevTask == null || nextTask == null) {
                return;
            }
        }

    }


    @Override
    public boolean isCancelled() {
        return false;
    }

    @Override
    public void cancel() {
        // Nothing to do
    }

}
