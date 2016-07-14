var jwt = require('json-web-token');

var secret = "secret12#";
/**
 * Implicit AWS API Gateway Custom Authorizer. Validates the JWT token passed
 * into the Authorization header for all requests.
 * 
 * @param {Object}
 *            event [description]
 * @param {Object}
 *            context [description]
 * @return {Object} [description]
 */
exports.handler = function(event, context) {
	var token = event.authorizationToken;

	jwt.decode(secret, token, function(ex, decode) {
		if (ex) {
			console.log("Invalid token");
			console.error(ex.name + ": " + ex.message);
			context.done(null, generatePolicy("user", 'Deny',
					event.methodArn));
		} else {
			console.log("Valid token");
			console.log(decode);
			context.done(null, generatePolicy(decode.sub, 'Allow',
					decode.permissions));
		}
	});
};

function generatePolicy(principalId, effect, resource) {
	console.log("GeneratePolicy");
	var authResponse = {};
	authResponse.principalId = principalId;
	if (effect && resource) {
		var policyDocument = {};
		policyDocument.Version = '2012-10-17'; // default version
		policyDocument.Statement = [];
		var statementOne = {};
		statementOne.Action = 'execute-api:Invoke'; // default action
		statementOne.Effect = effect;
		statementOne.Resource = resource;
		policyDocument.Statement[0] = statementOne;
		authResponse.policyDocument = policyDocument;
	}
	return authResponse;
}