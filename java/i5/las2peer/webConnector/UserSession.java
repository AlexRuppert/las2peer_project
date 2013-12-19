package i5.las2peer.webConnector;

import java.util.HashMap;


import i5.las2peer.security.Mediator;

/**
 * Stores {@link Mediator} and registered services (+ times) for a user
 * @author Alexander
 *
 */
public class UserSession {
	private Mediator _agentMediator;
	
	private HashMap<String,Long> _services;
	public Mediator getMediator()
	{
		return _agentMediator;
	}
	
	public UserSession(Mediator mediator)
	{
		_services=new HashMap<String,Long>();
		_agentMediator=mediator;
		
	}
	public void updateServiceTime(String service, long time)
	{
		_services.put(service, time);
	}
	public HashMap<String,Long> getServices() {
		
		return _services;
	}
}
