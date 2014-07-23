/*
 * Copyright 2014 Georgia Tech Research Institute
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package edu.internet2.middleware.assurance.mcb.authn.provider;

import edu.internet2.middleware.assurance.mcb.authn.provider.MCBLoginServlet;
import edu.internet2.middleware.assurance.mcb.authn.provider.MCBSubmodule;
import edu.internet2.middleware.assurance.mcb.authn.provider.MCBUsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.Math;
import org.apache.velocity.VelocityContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This sub-module handles generic second factor code input.
 * 
 * @author Not Applicable
 */
public class CodeSubmodule implements MCBSubmodule{

	private final Logger log = LoggerFactory.getLogger(CodeSubmodule.class);

	private String beanName = null;

	private String loginPage;
        private String TokenName = "RandomToken";

	/**
	 * Constructor
	 * @param loginPage velocity template containing code input page
	 */
	public CodeSubmodule(String loginPage){
		this.loginPage = loginPage;

		log.debug("Config: login page: {}", loginPage);
	}

	/**
	 * Display the Code Input Screen
	 * 
	 * @param servlet
	 * @param request
	 * @param response
	 * @return
	 * @throws AuthenticationException
	 * @throws LoginException 
	 */
	public boolean displayLogin(MCBLoginServlet servlet, HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, LoginException {
		//this module must be invoked after a principal has already been established
		MCBUsernamePrincipal principal = (MCBUsernamePrincipal) request.getSession().getAttribute(LoginHandler.PRINCIPAL_KEY);
		log.debug("principal name is: {}", principal.getName());
		if(principal == null || principal.getName() == null || principal.getName().equals("") || principal.getName().equals("[principal]")){
			log.error("The CodeSubmodule may not be invoked unless the user already has authenticated using another method.  No user principal detected.");
			return false;
		}

                //insert a check for code cookie...  TBD...	

                // Generate a random token
                int Token = (int)10000 + (int)(Math.random() * 90000);  // Generates a random 5 digit number between 10,000 and 99,999.

		log.debug("Generating a random token ({}) for principal: {}", Token, principal);

                // Adding token to the session.
                request.getSession().setAttribute(TokenName, Token);


		VelocityContext vCtx = new VelocityContext();

		log.debug("Displaying Velocity Token template [{}]",loginPage);
		servlet.doVelocity(request, response, loginPage, vCtx);

		return true;
	}

	/**
	 * Process the response from the Login Screen
	 * @param servlet
	 * @param request
	 * @param response
	 * @return
	 * @throws AuthenticationException
	 * @throws LoginException 
	 */
	public boolean processLogin(MCBLoginServlet servlet, HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, LoginException {
		MCBUsernamePrincipal principal = (MCBUsernamePrincipal) request.getSession().getAttribute(LoginHandler.PRINCIPAL_KEY);

		Integer TokenInput = new Integer(DatatypeHelper.safeTrimOrNullString(request.getParameter("code")));
                Integer TokenValue = (Integer) request.getSession().getAttribute(TokenName);

		log.debug("Comparing input token {} to generated token {}", TokenInput, TokenValue);

		if( TokenInput.intValue() != TokenValue){
			log.error("User inputed invalid token. Removing token from session.");
			principal.setFailedLogin("Invalid token input.");
                        request.getSession().removeAttribute(TokenName);
			return false;
		}

		log.debug("User Token Valid.  Generating Cookie...");

                // Insert Cookie Code...  
                
		return true;
	}

	public void init() {
		log.info("Code Login Submodule version {} initialized", getClass().getPackage().getImplementationVersion());
	}

	public String getBeanName() {
		return beanName;
	}

	public void setBeanName(String string) {
		beanName = string;
	}

}


