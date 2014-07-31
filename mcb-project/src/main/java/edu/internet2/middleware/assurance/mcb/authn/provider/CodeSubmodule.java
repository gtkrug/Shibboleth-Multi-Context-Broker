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
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import java.lang.Math;
import java.io.IOException;
import java.util.ArrayList;
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
        private int    ValidityWindow; 
        private String emailAttributeId;
        private String EmailSessionVariable =  "EmailAddress";
        private String TokenName            =  "RandomToken";
        private String CookieName           =  "__idp_second_factor_cached"; 
        private String cached               =  "cached2nd";

	/**
	 * Constructor
	 * @param loginPage velocity template containing code input page
	 * @param validDays the number of days for which this browser is validated as a second factor
	 */
	public CodeSubmodule(String loginPage, Integer validDays, String emailAttribute) {
		this.loginPage = loginPage;
                this.ValidityWindow = validDays.intValue();
                this.emailAttributeId = emailAttribute;
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

                // Setting up the velocity context
		VelocityContext vCtx = new VelocityContext();


                // Generate a random token
                int Token = (int)10000 + (int)(Math.random() * 90000);  // Generates a random 5 digit number between 10,000 and 99,999.

                // Adding token to the session.
                request.getSession().setAttribute(TokenName, Token);

                // Check for a cookie to determine if 2nd factor is required.
                String cookieEmail = GetCookie (request, CookieName);
                if ( cookieEmail != null ) {
                   log.debug("The user's browser has a 2nd factor cookie setting 2nd factor fulfilled.");
                   vCtx.put(cached, "true");
                }
                else { // Second factor is required
                   vCtx.put(cached, "false");

                   // Get the user's e-mail address...
                   String EmailAddress = ResolveAttribute (servlet, request, response, principal.getName(), emailAttributeId);
                    
                   request.getSession().setAttribute(EmailSessionVariable, EmailAddress);

                   // Send Token via e-mail...
                   log.debug("Emailing random token ({}) to email: {}", Token, EmailAddress);
                }

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

                // Check to see if we have a valid 2nd factor cookie...
                if ( GetCookie(request,CookieName) != null) {
                    return true;
                }

		Integer TokenInput = new Integer(DatatypeHelper.safeTrimOrNullString(request.getParameter("code")));
                Integer TokenValue = (Integer) request.getSession().getAttribute(TokenName);
		Boolean RememberMe = new Boolean(DatatypeHelper.safeTrimOrNullString(request.getParameter("RememberMe")));

		log.debug("Comparing input token {} to generated token {}", TokenInput, TokenValue);

		if( TokenInput.intValue() != TokenValue){
			log.error("User inputed invalid token. Removing token from session.");
			principal.setFailedLogin("Invalid token input.");
                        request.getSession().removeAttribute(TokenName);
			return false;
		}

                // User did input the correct 2nd factor, so adding a cookie for them.
                if ( RememberMe )
                {
		  log.debug("User Token Valid.  Generating Cookie...");
                  String EmailAddress = (String) request.getSession().getAttribute(EmailSessionVariable);
                  Cookie cookie = new Cookie(CookieName,EmailAddress);
		  cookie.setMaxAge(60*60*24*ValidityWindow); //Seconds in a Day x Days Valid
		  response.addCookie(cookie);
                }
 
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

        public String GetCookie (HttpServletRequest request, String cookieName) {
              Cookie[] requestCookies = request.getCookies();

              for (Cookie c : requestCookies) {
                 log.debug("Cookie {} = {}", c.getName(), c.getValue() );
                 if ( cookieName.equals(c.getName()) ) {
                    // Found a code cookie
                    return c.getValue();
                 }
             }

             return null;
        }

        public String ResolveAttribute (MCBLoginServlet servlet, HttpServletRequest request, HttpServletResponse response, String principal, String Attribute) {

           try {
             MCBAttributeResolver ar = new MCBAttributeResolver();
             log.debug("Running attribute resolution for principal [{}]", principal);

             String entityID = "urn:all"; // Dummy entityID...  If it matters for this type of resolution will replace later.

             ar.resolve(servlet, request, response, principal, entityID);

             BaseAttribute ba = ar.getAttributes().get(Attribute);
             log.debug("Found e-mail attribute: {}", ba);

             ArrayList<String> emailAddresses = ar.getValueList(ba);

            if ( emailAddresses.size() >= 1 )
            {
              // Return the first email address found.
              log.debug("Returning email address: {}", emailAddresses.get(0));
              return emailAddresses.get(0);
            }
        } catch ( AuthenticationException e ) {
           log.error("Authentication exception while trying to resolve EmailAddress:", e);
        }

        log.error("Could not resolve EmailAddress for principal [{}]", principal);
        return null;
     }
}


