package com.load8.oauth.load8oauth.controller;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.lumeris.innovation.oauth.common.DataStore;
import com.lumeris.innovation.oauth.controllers.MongoDbBasicResult;
import com.lumeris.innovation.oauth.models.PolicyConfiguration;
import com.lumeris.innovation.oauth.models.RegisteredClient;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiOperation;

@RestController
@Api(
		value = "Registration",
		description = "Methods to manage client registrations",
		consumes = "application/json",
		produces = "application/json")
public class RegisterClientController {
	
	@ApiOperation(
			httpMethod = "POST",
			value = "register a new client",
			consumes = "application/json",
			produces = "application/json",
			response = RegisteredClient.class)
	@RequestMapping(value = "oauth/client", method = RequestMethod.POST)
	public RegisteredClient post(@RequestBody RegisteredClient request) throws Exception {
		// validate
		if (request == null)
			throw new Exception("post body must be specified");
		if (StringUtils.isBlank(request.getName()))
			throw new Exception("Name must be specified");
		if (StringUtils.isBlank(request.getCreatedBy()))
			throw new Exception("CreatedBy must be specified");

		// validate id
		if (StringUtils.isNotBlank(request.getId()))
			validateId(request.getId());
		else
			request.setId(IdProvider.next());

		// initialize properties
		request.setAuthorizationId(IdProvider.nextLongUuid());
		if (StringUtils.isBlank(request.getOwner()))
			request.setOwner(request.getCreatedBy());
		if (StringUtils.isBlank(request.getSecret()))
			request.setSecret(IdProvider.nextRandom(40));
		PolicyConfiguration policy = request.getPolicy();
		if (policy == null)
			policy = new PolicyConfiguration();
		if (policy.getAccessTokenLifetime() <= 0)
			policy.setAccessTokenLifetime(PolicyConfiguration.DefaultAccessTokenExpiry);
		if (policy.getRefreshTokenLifetime() <= 0)
			policy.setRefreshTokenLifetime(PolicyConfiguration.DefaultRefreshTokenExpiry);
		request.setPolicy(policy);
		request.setCreatedAt(DateTime.now(DateTimeZone.UTC));
		request.setModifiedBy(request.getCreatedBy());
		request.setModifiedAt(request.getCreatedAt());

		// save
		MongoDbBasicResult result = DataStore.oAuth().save(request);
		if (!result.getOk())
			throw new Exception(result.getErrorMessage());

		return request;
	}

}
