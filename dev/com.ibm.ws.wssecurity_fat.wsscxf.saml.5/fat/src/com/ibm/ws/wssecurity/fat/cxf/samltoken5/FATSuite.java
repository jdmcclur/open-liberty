/*******************************************************************************
 * Copyright (c) 2021 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/

package com.ibm.ws.wssecurity.fat.cxf.samltoken5;

import org.junit.ClassRule;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.ibm.ws.wssecurity.fat.cxf.samltoken5.LiteAlwaysRunTest.AlwaysRunAndPassTest;
import com.ibm.ws.wssecurity.fat.cxf.samltoken5.OneServerTests.CxfSAMLSymSignEnc1ServerTests;
import com.ibm.ws.wssecurity.fat.cxf.samltoken5.TwoServerTests.CxfSAMLSymSignEnc2ServerTests;
import com.ibm.ws.wssecurity.fat.cxf.samltoken5.OneServerTests.CxfSAMLAsymSignEnc1ServerTests;
import com.ibm.ws.wssecurity.fat.cxf.samltoken5.TwoServerTests.CxfSAMLAsymSignEnc2ServerTests;


import componenttest.rules.repeater.EmptyAction;
import componenttest.rules.repeater.FeatureReplacementAction;
import componenttest.rules.repeater.RepeatTests;

@RunWith(Suite.class)
@SuiteClasses({

	   //Lite
	   AlwaysRunAndPassTest.class,
             
       //Full
       CxfSAMLSymSignEnc2ServerTests.class, 
       CxfSAMLAsymSignEnc2ServerTests.class,
       CxfSAMLSymSignEnc1ServerTests.class, 
       CxfSAMLAsymSignEnc1ServerTests.class
          
              
})


/**
 * Purpose: This suite collects and runs all known good test suites.
 */
public class FATSuite {

	//The following repeats run Lite only for local testing
    //@ClassRule
    //public static RepeatTests r = RepeatTests.withoutModification().andWith(FeatureReplacementAction.EE8_FEATURES().removeFeature("jsp-2.2").removeFeature("jaxws-2.2").removeFeature("servlet-3.1").removeFeature("usr:wsseccbh-1.0").addFeature("jsp-2.3").addFeature("jaxws-2.3").addFeature("servlet-4.0").addFeature("usr:wsseccbh-2.0"));

    //The following repeats run both Full and Lite buckets.
    //To run Full only single test class locally,  using the command option "-Dfat.test.class.name";
    //To run Full only entire bucket locally, comment out the Lite bucket above
    @ClassRule
    public static RepeatTests r = RepeatTests.with(new EmptyAction().fullFATOnly()).andWith(FeatureReplacementAction.EE8_FEATURES().removeFeature("jsp-2.2").removeFeature("jaxws-2.2").removeFeature("servlet-3.1").removeFeature("usr:wsseccbh-1.0").addFeature("jsp-2.3").addFeature("jaxws-2.3").addFeature("servlet-4.0").addFeature("usr:wsseccbh-2.0"));

}
