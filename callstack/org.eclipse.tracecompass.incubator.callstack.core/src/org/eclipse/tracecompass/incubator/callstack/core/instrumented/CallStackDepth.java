/*******************************************************************************
 * Copyright (c) 2018 École Polytechnique de Montréal
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.callstack.core.instrumented;

import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.incubator.callstack.core.flamechart.CallStack;

import com.google.common.base.Objects;

/**
 * A class that associates a callstack with a depth, to abstract the state
 * system accesses.
 *
 * @author Geneviève Bastien
 */
public class CallStackDepth {

    private final CallStack fCallstack;
    private final int fDepth;

    /**
     * Constructor. The caller must make sure that the callstack has the requested
     * depth.
     *
     * @param callstack
     *            The callstack
     * @param depth
     *            The depth of the callstack
     */
    public CallStackDepth(CallStack callstack, int depth) {
        fCallstack = callstack;
        fDepth = depth;
    }

    /**
     * Get the quark corresponding to this callstack depth
     *
     * @return The quark at this depth
     */
    public int getQuark() {
        return fCallstack.getQuarkAtDepth(fDepth);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(fCallstack, fDepth);
    }

    @Override
    public boolean equals(@Nullable Object obj) {
        if (!(obj instanceof CallStackDepth)) {
            return false;
        }
        CallStackDepth csd = (CallStackDepth) obj;
        return Objects.equal(fCallstack, csd.fCallstack) && (fDepth == csd.fDepth);
    }

}
