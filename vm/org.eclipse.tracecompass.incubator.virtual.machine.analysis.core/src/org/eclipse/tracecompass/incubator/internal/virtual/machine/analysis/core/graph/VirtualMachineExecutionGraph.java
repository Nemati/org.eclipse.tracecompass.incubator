/*******************************************************************************
 * Copyright (c) 2017 École Polytechnique de Montréal
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.graph;

import org.eclipse.tracecompass.analysis.graph.core.building.ITmfGraphProvider;
import org.eclipse.tracecompass.internal.lttng2.kernel.core.analysis.graph.building.LttngKernelExecGraphProvider;
import org.eclipse.tracecompass.internal.lttng2.kernel.core.analysis.graph.building.LttngKernelExecutionGraph;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;

/**
 * Execution graph of LTTng traces representing a VM analysis
 *
 * TODO: There should be no need to extend the base analysis, instead, it should
 * be just possible to add handlers to the original analysis
 *
 * @author Geneviève Bastien
 */
@SuppressWarnings("restriction")
public class VirtualMachineExecutionGraph extends LttngKernelExecutionGraph {

    @Override
    protected ITmfGraphProvider getGraphProvider() {
        ITmfTrace trace = getTrace();
        if (trace == null) {
            throw new NullPointerException();
        }
        return new LttngKernelExecGraphProvider(trace);
    }
}
