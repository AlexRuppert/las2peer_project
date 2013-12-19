package i5.las2peer.webConnector;

import i5.httpServer.HttpRequest;
import i5.httpServer.HttpResponse;
import i5.httpServer.RequestHandler;
import i5.las2peer.execution.NoSuchServiceException;
import i5.las2peer.execution.NoSuchServiceMethodException;
import i5.las2peer.execution.ServiceInvocationException;
import i5.las2peer.webConnector.WebConnector;


import i5.las2peer.httpConnector.coder.CodingException;
import i5.las2peer.httpConnector.coder.InvalidCodingException;
import i5.las2peer.p2p.AgentNotKnownException;
import i5.las2peer.p2p.Node;
import i5.las2peer.p2p.TimeoutException;
import i5.las2peer.security.Agent;
import i5.las2peer.security.L2pSecurityException;
import i5.las2peer.security.Mediator;
import i5.las2peer.security.PassphraseAgent;


import java.io.Serializable;

import java.io.UnsupportedEncodingException;

import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;



import rice.p2p.util.Base64;


/**
 * A HttpServer RequestHandler for handling requests to the LAS2peer web connector.
 * No real session management (because RESTful requirements)
 * Instead an account is not instantly logged out, to allow internal write buffering, before writing to a DB
 *
 * Current Problem (LAS related, maybe out-dated..):
 * This class will be used by an library (the HttpServer), so it has to be provided
 * as an library as well. To gain access to the configuration parameters the way
 * back to the service will be needed, but this is not allowed by the las class loaders.
 *
 * @author Holger Jan&szlig;en
 * @author Alexander
 */



public class WebConnectorRequestHandler implements RequestHandler {

	private static final int LOGOUT_INTERVAL = 10;
	private static final String REST_DECODER = "restDecoder";
	private static final String CLEAN_UP_METHOD="cleanUp";
	private static final String AUTHENTICATION_FIELD = "Authentication";
	private static final int DEFAULT_TIMEMOUT=10000;//ms
	private WebConnector connector;
	private Node l2pNode;
	private Hashtable<Long, UserSession> _userSessions;
	private long _currentUserId=-1;
	private ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor(); 
	        


	//private Agent anonymous = null;
	//private Mediator mediator=null;
	/**
	 * Standard Constructor
	 *
	 */
	public WebConnectorRequestHandler () {		
		_userSessions = new Hashtable<Long, UserSession>(); //manage all active sessions
		
	    scheduledExecutorService.scheduleWithFixedDelay( //thread looping and checking for timeouts
	    		new Runnable() {						//if the user is logged in for too long without sending any requests-> logout
			        public void run() {					
			        	checkforLogout(false);
			           
			        }
			    }
	    		, LOGOUT_INTERVAL, LOGOUT_INTERVAL, TimeUnit.SECONDS);
			  


	}
	/**
	 * Checks if a user is logged in for too long into a service 
	 * without sending requests and logs them out after a period of time.
	 * @param forceAll logout all useres, regardless of any timeout
	 */
	private void checkforLogout(boolean forceAll)
	{
		Long currentTime=(new Date()).getTime();
		connector.logMessage("logout check");
		try
		{
			for (Long userId : _userSessions.keySet()) { //for each user
				UserSession sess=_userSessions.get(userId);	
				
				for (String  serviceName : sess.getServices().keySet()) //for each service
				{
					
					if(forceAll||sess.getServices().get(serviceName)+DEFAULT_TIMEMOUT<currentTime)//check timeout
					{
						
						logout(serviceName,userId); 
						try {
							connector.logMessage("Logout: "+l2pNode.getLoginForAgentId(userId));
						} catch (AgentNotKnownException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
				
			}
		}
		catch(Exception e)
		{
			
		}
		
	}
	/**
	 * Force logout for all users
	 */
	protected void finalize () throws Throwable
	{
		checkforLogout(true);
		scheduledExecutorService.shutdown();
	}
	/**
	 * set the connector handling this request processor
	 * @param connector
	 */
	public void setConnector ( WebConnector connector ) {
		this.connector = connector;
		l2pNode = connector.getL2pNode();
		
		//anonymous = l2pNode.getAnonymous();
	}
	/**
	 * Login user as a las2peer user
	 * @param request
	 * @param response
	 * @return true if user was logged in successfully
	 * @throws UnsupportedEncodingException
	 */
	private boolean authenticate (HttpRequest request, HttpResponse response) throws UnsupportedEncodingException
	{
		String[] requestSplit=request.getPath().split("/",3);
		if(requestSplit.length<2)
			return false;
		String serviceName=requestSplit[1];
		final int BASIC_PREFIX_LENGTH="BASIC ".length();
		String userPass="";
		String username="";
		String password="";
		
		//Check for authentication information in header
		if(request.hasHeaderField(AUTHENTICATION_FIELD)
				&&(request.getHeaderField(AUTHENTICATION_FIELD).length()>BASIC_PREFIX_LENGTH))
		{
			userPass=request.getHeaderField(AUTHENTICATION_FIELD).substring(BASIC_PREFIX_LENGTH);
			userPass=new String(Base64.decode(userPass), "UTF-8");
			int separatorPos=userPass.indexOf(':');
			//get username and password
			username=userPass.substring(0,separatorPos);
			password=userPass.substring(separatorPos+1);
			
			
			try
			{
				
				long userId;
				Agent userAgent;
				
				if ( username.matches ("-?[0-9].*") ) {
					try {
						userId = Long.valueOf(username);
					} catch ( NumberFormatException e ) {
						throw new L2pSecurityException ("The given user does not contain a valid agent id!");
					}
				} else {
					userId = l2pNode.getAgentIdForLogin(username);
				}
				
				userAgent = l2pNode.getAgent(userId);
				
				if ( ! (userAgent instanceof PassphraseAgent ))
					throw new L2pSecurityException ("Agent is not passphrase protected!");
				((PassphraseAgent)userAgent).unlockPrivateKey(password);
				_currentUserId=userId;
				
				if(!_userSessions.containsKey(userId))//if user not registered
				{				
					Mediator mediator = l2pNode.getOrRegisterLocalMediator(userAgent);
					_userSessions.put(userId, new UserSession(mediator));
					
				}
				
				_userSessions.get(userId).updateServiceTime(serviceName,new Date().getTime());//update last access time for service
				
				connector.logMessage("Login: "+username);
				connector.logMessage("Sessions: "+Integer.toString(_userSessions.size()));
				
				return true;
				
			}catch (AgentNotKnownException e) {
				sendUnauthorizedResponse(response, null, request.getRemoteAddress() + ": login denied for user " + username);
			} catch (L2pSecurityException e) {
				sendUnauthorizedResponse( response, null, request.getRemoteAddress() + ": unauth access - prob. login problems");
			} catch (Exception e) {
				
				sendInternalErrorResponse(
						response, 
						"The server was unable to process your request because of an internal exception!", 
						"Exception in processing create session request: " + e);
			}
			
		}
		else
		{
			response.setStatus ( HttpResponse.STATUS_BAD_REQUEST );
			response.setContentType( "text/plain" );
			response.print ( "No authentication provided!" );
			connector.logError( "No authentication provided!" );
		}
		return false;
	}
	/**
	 * Handles a request (login, invoke)
	 */
	@Override
	public void processRequest(HttpRequest request, HttpResponse response) throws Exception {
		response.setHeaderField( "Server-Name", "Las2peer 0.1" );
		response.setContentType( "text/xml" );
		
		
		
		if(authenticate(request,response))
			if(invoke(request,response));
				//logout(_currentUserId);
	 
	
		//connector.logMessage(request.toString());
		
		
	}
	/**
	 * Logs the user out. Calls a cleanUp() method of the service, if available.
	 * @param serviceName
	 * @param userId
	 */
	private void logout(String serviceName, long userId)
	{
		try {
			Mediator mediator=_userSessions.get(userId).getMediator();			
			try { //clean up buffers etc before logout
				mediator.invoke(serviceName,CLEAN_UP_METHOD, new Serializable[]{}, connector.preferLocalServices());
			} catch (Exception e) {				
				//pssst, don't bother anyone, if service has no cleanUp method (is not required by service interface)
			}
			
			
			
			_userSessions.get(userId).getServices().remove(serviceName); //cleanup userSessions
			if(_userSessions.get(userId).getServices().size()<=0)
			{
				_userSessions.remove(userId);
				Agent userAgent =l2pNode.getAgent(mediator.getResponsibleForAgentId());
				l2pNode.unregisterAgent(userAgent);
				((PassphraseAgent)userAgent).lockPrivateKey();//don't know if really necessary
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	/**
	 * Delegates the request data to a service method, which then decides what to do with it (maps it internally)
	 * @param request
	 * @param response
	 * @return
	 */
	private boolean invoke(HttpRequest request, HttpResponse response) {
		
		String[] requestSplit=request.getPath().split("/",3);
		// first: empty (string starts with '/')
		// second: service name
		// third: URI rest
		String serviceName="";
		String methodName="";
		String restURI="";
		String content="";
		
		try {
			
			serviceName=requestSplit[1];
			methodName=REST_DECODER; //special method in service
			
			if(requestSplit.length>=3)
			{
				int varsstart=requestSplit[2].indexOf('?');
				if(varsstart>0)
					restURI=requestSplit[2].substring(0,varsstart);
				else
					restURI=requestSplit[2];
			}
			
			content=request.getContentString();
			
			int httpMethodInt=request.getMethod();
			String httpMethod="get";
			
			switch (httpMethodInt) 
			{
				case HttpRequest.METHOD_GET:
					httpMethod="get";
					break;
				case HttpRequest.METHOD_HEAD:
					httpMethod="head";
					break;
				case HttpRequest.METHOD_DELETE:
					httpMethod="delete";
					break;
				case HttpRequest.METHOD_POST:
					httpMethod="post";
					break;
				case HttpRequest.METHOD_PUT:
					httpMethod="put";
					break;
				default:
					break;
			}
			if(content==null)
				content="";
			
			
			
			
			String[][] variables = {};//extract variables from request
			
			ArrayList<String[]> variablesList=new ArrayList<String[]>();
			@SuppressWarnings("rawtypes")
			Enumeration en = request.getGetVarNames();		
			String querystr="";
			while(en.hasMoreElements())
			{
				String param = (String) en.nextElement();
				String val= request.getGetVar(param);
				
				String[] pair={param,val};
				//connector.logMessage(param+" "+val);
				variablesList.add(pair);
				querystr+=param+" = "+val+" ";
			}
			connector.logMessage(request.getMethod()+" "+request.getUrl()+" "+querystr);
			variables=variablesList.toArray(new String[variablesList.size()][2]);
			
			//connector.logMessage(content);
			Serializable[] parameters={httpMethod,restURI,variables,content};
			
			Serializable result;	
			Mediator mediator = _userSessions.get(_currentUserId).getMediator();//get registered mediator
			result= mediator.invoke(serviceName,methodName, parameters, connector.preferLocalServices());// invoke service method
			
			sendInvocationSuccess ( result, response );
			return true;
			
		} catch ( NoSuchServiceException e ) {
			sendNoSuchService(request, response, serviceName);			
		} catch ( TimeoutException e ) {
			sendNoSuchService(request, response, serviceName);
		} catch ( NoSuchServiceMethodException e ) {
			sendNoSuchMethod(request, response);
		} catch ( L2pSecurityException e ) {
			sendSecurityProblems(request, response, e);					
		} catch ( ServiceInvocationException e ) {
			if ( e.getCause() == null )
				sendResultInterpretationProblems(request, response);
			else
				sendInvocationException(request, response, e);								
		} catch ( InterruptedException e ) {
			sendInvocationInterrupted(request, response);
		} catch ( InvalidCodingException e ) {
			sendConnectorProblems(request, response, e);
		} catch ( CodingException e ) {
			sendResultInterpretationProblems(request, response);
		} catch (Exception e)
		{
		
		}
		return false;
	}
	/**
	 * send a response, that the connector has problems to interpret the 
	 * incoming invocation request
	 * 
	 * @param request
	 * @param response
	 * @param sid
	 * @param e
	 */
	private void sendConnectorProblems(HttpRequest request,
			HttpResponse response, Exception e) {
		response.clearContent();
		response.setStatus( HttpResponse.STATUS_NOT_ACCEPTABLE );
		response.setContentType( "text/plain" );
		response.println ( "The invocation parameters could not be read!" );
		response.println ( "Exception-Message: " + e.getMessage() );
		connector.logError("Request coding exception in invocation request " + request.getPath());
	}
	/**
	 * send a notification about an exception which occurred inside the requested service method
	 * 
	 * @param request
	 * @param response
	 * @param sid
	 * @param e
	 */
	private void sendInvocationException(HttpRequest request,
			HttpResponse response, ServiceInvocationException e) {
		// internal exception in service method
		response.clearContent();
		response.setStatus( HttpResponse.STATUS_INTERNAL_SERVER_ERROR );
		response.setContentType( "text/xml" );
		connector.logError("Exception while processing RMI: " + request.getPath());
		
		Object[] ret = new Object[4];
		ret[0] = "Exception during RMI invocation!";
		
		ret[1] = e.getCause().getCause().getClass().getCanonicalName();
		ret[2] = e.getCause().getCause().getMessage();
		ret[3] = e.getCause().getCause();
		String code = ret[0]+"\n"+ret[1]+"\n"+ret[2]+"\n"+ret[3];
		response.println ( code );
	}
	/**
	 * send a notification, that the result of the service invocation is
	 * not transportable 
	 * 
	 * @param request
	 * @param response
	 * @param sid
	 */
	private void sendResultInterpretationProblems(HttpRequest request,
			HttpResponse response) {
		// result interpretation problems
		response.clearContent();
		response.setStatus( HttpResponse.STATUS_INTERNAL_SERVER_ERROR );
		response.setContentType( "text/xml" );
		response.println ("the result of the method call is not transferable!");
		connector.logError("Exception while processing RMI: " + request.getPath());
	}
	/**
	 * send a notification, that security problems occurred during the requested service method
	 * @param request
	 * @param response
	 * @param sid
	 * @param e
	 */
	private void sendSecurityProblems(HttpRequest request,
			HttpResponse response, L2pSecurityException e) {
		response.clearContent();
		response.setStatus( HttpResponse.STATUS_FORBIDDEN );
		response.setContentType( "text/plain" );
		response.println ( "You don't have access to the method you requested" );
		connector.logError("Security exception in invocation request " + request.getPath());
		
		if ( System.getProperty("http-connector.printSecException") != null
				&& System.getProperty( "http-connector.printSecException").equals ( "true" ) )
			e.printStackTrace();
	}
	/**
	 * send a notification, that the requested method does not exists at the requested service
	 * @param request
	 * @param response
	 * @param sid
	 */
	private void sendNoSuchMethod(HttpRequest request, HttpResponse response) {
		response.clearContent();
		response.setStatus( HttpResponse.STATUS_NOT_FOUND );
		response.setContentType( "text/plain" );
		response.println ( "The method you requested is not known to this service!" );
		connector.logError("Invocation request " + request.getPath() + " for unknown service method");
	}


	/**
	 * send a notification, that the requested service does not exists
	 * @param request
	 * @param response
	 * @param sRequest
	 */
	private void sendNoSuchService(HttpRequest request, HttpResponse response,
			String service) {
		response.clearContent();
		response.setStatus( HttpResponse.STATUS_SERVICE_UNAVAILABLE );
		response.setContentType( "text/plain" );
		response.println ( "The service you requested is not known to this server!" );
		
		connector.logError ("Service not found: " +service);
	}
	/**
	 * 
	 * @param result
	 * @param response
	 * @throws CodingException 
	 */
	private void sendInvocationSuccess ( Serializable result, HttpResponse response  ) throws CodingException {
		if ( result != null ) {
			response.setContentType( "text/xml" );
			String resultCode =  (result.toString());
			response.println ( resultCode );
		} else {
			response.setStatus( HttpResponse.STATUS_NO_CONTENT );
		}
	}
	/**
	 * send a notification, that the processing of the invocation has been interrupted
	 * 
	 * @param request
	 * @param response
	 */
	private void sendInvocationInterrupted(HttpRequest request,
			HttpResponse response) {
		response.clearContent();
		response.setStatus (HttpResponse.STATUS_INTERNAL_SERVER_ERROR );
		response.setContentType ( "text/plain");
		response.println ( "The invoction has been interrupted!");
		connector.logError("Invocation has been interrupted!");
	}
	/**
	 * send a response that an internal error occurred
	 * 
	 * @param response
	 * @param answerMessage
	 * @param logMessage
	 */
	private void sendInternalErrorResponse(HttpResponse response,
			String answerMessage, String logMessage) {
		response.clearContent();
		response.setContentType( "text/plain" );
		response.setStatus( HttpResponse.STATUS_INTERNAL_SERVER_ERROR );
		response.println ( answerMessage );
		connector.logMessage ( logMessage );
	}


	/**
	 * send a message about an unauthorized request
	 * @param response
	 * @param logMessage
	 */
	private void sendUnauthorizedResponse(HttpResponse response, String answerMessage,
			String logMessage) {
		response.clearContent();
		response.setContentType( "text/plain" );
		if ( answerMessage != null)
			response.println ( answerMessage );
		response.setStatus( HttpResponse.STATUS_UNAUTHORIZED );
		connector.logMessage ( logMessage  );
	}

	
	/**
	 * encapsulates the coding of a service method invocation result in terms
	 * of this protocol.
	 *
	 * @param    result         an Object
	 *
	 * @return   a String 		The coding of the resulting object as String to be
	 * 							send as http response content.
	 *
	 * @exception   ParameterTypeNotImplementedException 	The class of the result cannot be coded via this protocol
	 * @exception   ConnectorException 						Internal problems
	 *
	 */
	
	
	
}



