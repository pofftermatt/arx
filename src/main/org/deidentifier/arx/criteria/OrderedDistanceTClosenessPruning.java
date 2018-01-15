/*
 * ARX: Powerful Data Anonymization
 * Copyright 2012 - 2017 Fabian Prasser, Florian Kohlmayer and contributors
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.deidentifier.arx.criteria;

import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.FastIntDoubleMap;
import org.deidentifier.arx.certificate.elements.ElementData;
import org.deidentifier.arx.framework.check.groupify.HashGroupifyEntry;
import org.deidentifier.arx.framework.data.DataManager;
import org.deidentifier.arx.framework.lattice.Transformation;

import com.carrotsearch.hppc.IntDoubleOpenHashMap;

/**
 * The t-closeness criterion for ordered attributes.
 *
 * @author Fabian Prasser
 * @author Florian Kohlmayer
 */
public class OrderedDistanceTClosenessPruning extends TCloseness {

    /** SVUID */
    private static final long serialVersionUID = -2395544663063577862L;

    /** The original distribution. */
    private double[]          distribution;

    /** The order of the elements. */
    private int[]             order;

    /** The order of the elements. */
    private int[]             orderNumber;
    
    /** Partial distances of the original distribution. */
    private double[]          baseDistances;
    
    /** Partial sums of the original distribution. */
    private double[]          baseSums;

    /** Minimal order number that must be present */
    private int               minOrder;
    
    public boolean MEASURE_TOTAL_TIME = false;
	public boolean MEASURE_BLOCKS = false;
	public boolean COUNT_ABORTS = false;
	public long TOTAL_CALLS = 0l;
	public long ABORTS = 0l;
	public long TIME_BLOCK_1 = 0l;
	public long TIME_BLOCK_2 = 0l;
	public long TOTAL_TIME = 0l;

	private long time_overall = 0l;
	private long time_blocks = 0l;

    /**
     * Creates a new instance of the t-closeness criterion for ordered attributes as proposed in:
     * Li N, Li T, Venkatasubramanian S.
     * t-Closeness: Privacy beyond k-anonymity and l-diversity.
     * 23rd International Conference on Data Engineering. 2007:106-115.
     *
     * @param attribute
     * @param t
     */
    public OrderedDistanceTClosenessPruning(String attribute, double t) {
        super(attribute, t);
    }

    @Override
    public OrderedDistanceTClosenessPruning clone() {
        return new OrderedDistanceTClosenessPruning(this.getAttribute(), this.getT());
    }
    
    @Override
    public void initialize(DataManager manager, ARXConfiguration config) {
		super.initialize(manager, config);
		this.distribution = manager.getDistribution(attribute);
		this.order = manager.getOrder(attribute);
		this.orderNumber = getOrderNumbers(order);
		this.baseDistances = new double[order.length];
		this.baseSums = new double[order.length];
        
        double threshold = t * (order.length - 1d);
        double distance = 0d;
        double sum_i = 0d;

        // Find minimal order number that must be present and initialize base distances and sums
        this.minOrder = order.length;
        for (int orderNum = 0; orderNum < order.length; orderNum++) {
            
            // Compute summands and distances
            int value = order[orderNum];
            sum_i -= distribution[value];
            distance += Math.abs(sum_i);
            baseDistances[orderNum] = distance;
            baseSums[orderNum] = sum_i;
            
            // Check
            if (distance > threshold) {
                this.minOrder = orderNum;
                break;
            }
        }
    }

    @Override
    public boolean isAnonymous(Transformation node, HashGroupifyEntry entry) {
    	
    	if (COUNT_ABORTS || MEASURE_BLOCKS || MEASURE_TOTAL_TIME)
			TOTAL_CALLS++;
    	
		if (MEASURE_TOTAL_TIME)
			time_overall = System.nanoTime();
		if (MEASURE_BLOCKS)
			time_blocks = System.nanoTime();
		        
        // Init
        int[] buckets = entry.distributions[index].getBuckets();
        double count = entry.count;
        
        double threshold = t * (order.length - 1d);
        double sum_p = 0d;
        
        // Prepare
        int currentMinOrder = Integer.MAX_VALUE;
        FastIntDoubleMap map = new FastIntDoubleMap(buckets.length/2);
		for (int i = 0; i < buckets.length; i += 2) {
		    if (buckets[i] != -1) { // bucket not empty
		    	int value = buckets[i];
				double frequency = ((double) buckets[i + 1] / count);
				double dist = frequency - distribution[value];
				sum_p += dist;
				currentMinOrder = Math.min(currentMinOrder,  orderNumber[value]);
			if (Math.abs(sum_p) > threshold | Math.abs(dist) > threshold) {
				if (MEASURE_BLOCKS)
					TIME_BLOCK_1 += System.nanoTime() - time_blocks;
				if (MEASURE_TOTAL_TIME)
					TOTAL_TIME += System.nanoTime() - time_overall;
				if (COUNT_ABORTS)
					ABORTS++;
				return false;
			}
				map.put(value, dist);
		    }
		}
        
        if (currentMinOrder > this.minOrder) {
            // PRUNE
        	if (MEASURE_BLOCKS)
				TIME_BLOCK_1 += System.nanoTime() - time_blocks;
			if (MEASURE_TOTAL_TIME)
				TOTAL_TIME += System.nanoTime() - time_overall;
			if (COUNT_ABORTS)
				ABORTS++;
            return false;
        }
        
        if (MEASURE_BLOCKS) {
			TIME_BLOCK_1 += System.nanoTime() - time_blocks;
			time_blocks = System.nanoTime();
		}

        
        double distance = currentMinOrder > 0 ? baseDistances[currentMinOrder - 1] : 0d;
        double sum_i = currentMinOrder > 0 ? baseSums[currentMinOrder - 1] : 0d;
        
        // Calculate and check
        for (int i = currentMinOrder; i < order.length; i++) {
            
            // Compute summands and distance
		    int value = order[i];
		    sum_i += map.get(value, -distribution[value]);
            distance += Math.abs(sum_i);
            
            // Early abort
            if (distance > threshold) {
            	if (MEASURE_BLOCKS)
					TIME_BLOCK_2 += System.nanoTime() - time_blocks;
				if (MEASURE_TOTAL_TIME)
					TOTAL_TIME += System.nanoTime() - time_overall;
                return false;
            }
        }
        
        if (MEASURE_BLOCKS)
			TIME_BLOCK_2 += System.nanoTime() - time_blocks;
		if (MEASURE_TOTAL_TIME)
			TOTAL_TIME += System.nanoTime() - time_overall;
        // Yes
        return true;
    }

    @Override
    public boolean isLocalRecodingSupported() {
        return true;
    }

    @Override
    public ElementData render() {
        ElementData result = new ElementData("t-Closeness");
        result.addProperty("Attribute", attribute);
        result.addProperty("Threshold (t)", this.t);
        result.addProperty("Distance", "Ordered");
        return result;
    }

    @Override
    public String toString() {
        return t+"-closeness with ordered distance for attribute '"+attribute+"'";
    }

    /**
     * Maps values to order nums
     * @param order
     * @return
     */
    private int[] getOrderNumbers(int[] order) {
        int[] result = new int[order.length];
        for (int orderNum = 0; orderNum < order.length; orderNum++) {
            result[order[orderNum]] = orderNum;
        }
        return result;
    }
}
