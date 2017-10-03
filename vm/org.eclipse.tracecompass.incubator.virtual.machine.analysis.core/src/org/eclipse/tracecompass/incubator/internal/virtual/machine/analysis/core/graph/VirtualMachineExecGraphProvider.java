/*******************************************************************************
 * Copyright (c) 2017 École Polytechnique de Montréal
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.graph;

import org.eclipse.tracecompass.internal.lttng2.kernel.core.analysis.graph.building.LttngKernelExecGraphProvider;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;

/**
 * The execution graph provider
 *
 * @author Geneviève Bastien
 */
@SuppressWarnings("restriction")
public class VirtualMachineExecGraphProvider extends LttngKernelExecGraphProvider {

    /**
     * Constructor
     *
     * @param trace The trace this graph is for
     */
    public VirtualMachineExecGraphProvider(ITmfTrace trace) {
        super(trace);
        registerHandler(new KvmGraphHandler(this));
    }



}
