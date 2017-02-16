#include "Wt/WApplication"
#include "Wt/Auth/LinkedInService"
#include "Wt/Json/Object"
#include "Wt/Json/Parser"
#include "Wt/Http/Client"
#include "Wt/Json/Serializer"
#include <string>
#define ERROR_MSG(e) WString::tr("Wt.Auth.LinkedInService." e)

namespace {
  const char *RedirectEndpointProperty = "LinkedIn-oauth2-redirect-endpoint";
  const char *ClientIdProperty = "LinkedIn-oauth2-client-id";
  const char *ClientSecretProperty = "LinkedIn-oauth2-client-secret";
  const char *LinkedInPopupWidthProperty = "LinkediIn-oauth2-popupWidth";
  const char *LinkedInPopupHeightProperty = "LinkediIn-oauth2-popupHeight";

  const char *AuthUrl = "https://www.linkedin.com/uas/oauth2/authorization";
  const char *TokenUrl = "https://www.linkedin.com/uas/oauth2/accessToken";

  const char *DefaultScopeOfPermissions = "r_basicprofile r_emailaddress";
}

namespace Wt {

LOGGER("Auth.LinkedInService");

namespace Auth {

  class LinkedInProcess : public OAuthProcess
  {
  public:
    LinkedInProcess(const LinkedInService& auth, const std::string& scope, bool returnJsonInNameFieldOfIdentity = false)
      : OAuthProcess(auth, scope)
    { 
      this->getUserProfileAsJson = returnJsonInNameFieldOfIdentity;
    }

    // This call retrieves information about LinkedIn user: basic profile info and email address (as defined by the scope member variable):
    virtual void getIdentity(const OAuthAccessToken& token)
    {
      // Create Http REST client object:
      Http::Client *client = new Http::Client(this);
      client->setTimeout(15);
      client->setMaximumResponseSize(10*1024);

      // Tell how to handle the response:
      client->done().connect(boost::bind(&LinkedInProcess::handleMe, this, _1, _2));

      // Initialize request headers:
      std::vector<Http::Message::Header> headers;
      headers.push_back(Http::Message::Header("Authorization",
        "Bearer " + token.value()));

      const char *UserInfoUrl = "https://api.linkedin.com/v1/people/~:(id,num-connections,first-name,last-name,headline,location,email-address,positions,public-profile-url)?format=json";
      client->get(UserInfoUrl, headers);

#ifndef WT_TARGET_JAVA
      WApplication::instance()->deferRendering();
#endif
    }

  private:
    bool getUserProfileAsJson;
    // this method is called when REST response is received for request to get user information:
    void handleMe(boost::system::error_code err, const Http::Message& response)
    {
#ifndef WT_TARGET_JAVA
      WApplication::instance()->resumeRendering();
#endif

      if (!err && response.status() == 200) {
#ifndef WT_TARGET_JAVA
        Json::ParseError e;
        Json::Object me;
        bool ok = Json::parse(response.body(), me, e);
#else
        Json::Object me;
        try {
	         me = (Json::Object)Json::Parser().parse(response.body());
        } 
        catch (Json::ParseError pe) {
        }
        bool ok = me.isNull();
#endif

        if (!ok) {
	        LOG_ERROR("could not parse JSON: '" << response.body() << "'");
	        setError(ERROR_MSG("badjson"));
	        authenticated().emit(Identity::Invalid);
        } 
        else {
	        std::string id = me.get("id");
          std::string email = me.get("emailAddress");
          
          if (getUserProfileAsJson)
          {
            // In the Identity's name field more complete user info is passed in JSON format as returned from LinkedIn, see details at:
            // https://developer.linkedin.com/docs/fields/basic-profile
            authenticated().emit(Identity(service().name(), id, response.body(), email, true));
          }
          else
          {
            std::string name = me.get("firstName");
            name += std::string(" ");
            name += std::string(me.get("lastName"));
            authenticated().emit(Identity(service().name(), id, name, email, true));
          }
        }
      } 
      else {
        if (!err) {
	        LOG_ERROR("user info request returned: " << response.status());
	        LOG_ERROR("with: " << response.body());
        } 
        else {
          LOG_ERROR("handleMe(): " << err.message());
        }
        setError(ERROR_MSG("badresponse"));
        authenticated().emit(Identity::Invalid);
      }
    }
  };

  LinkedInService::LinkedInService(const AuthService& baseAuth, bool getUserProfileAsJson)
    : OAuthService(baseAuth)
  { 
    this->getUserProfileAsJson = getUserProfileAsJson;

    popupDialogWidth = 500;
    popupDialogHeight = 600;

    try
    {
      std::string propertyValue = configurationProperty(LinkedInPopupWidthProperty);
      popupDialogWidth = atoi(propertyValue.c_str());
    }
    catch (Wt::WException* e) 
    {    	
      LOG_ERROR("LinkedInService(): could not read configuration property " << LinkedInPopupWidthProperty << ": " << e->what() << ", using default value " << popupDialogWidth);
    }
    try
    {
      std::string propertyValue = configurationProperty(LinkedInPopupHeightProperty);
      popupDialogHeight = atoi(propertyValue.c_str());
    }
    catch (Wt::WException* e)
    {
      LOG_ERROR("LinkedInService(): could not read configuration property " << LinkedInPopupHeightProperty << ": " << e->what() << ", using default value " << popupDialogHeight);
    }
  }

  bool LinkedInService::configured()
  {
    try {
      configurationProperty(RedirectEndpointProperty);
      configurationProperty(ClientIdProperty);
      configurationProperty(ClientSecretProperty);
      return true;
    } 
    catch (const std::exception& e) {
      LOG_INFO("not configured: " << e.what());
      return false;
    }
  }    

  std::string LinkedInService::name() const
  {
    return "LinkedIn";
  }

  WString LinkedInService::description() const
  {
    return "LinkedIn Account";
  }

  std::string LinkedInService::authenticationScope() const
  {
    return DefaultScopeOfPermissions;
  }

  int LinkedInService::popupWidth() const
  {
    return popupDialogWidth;
  }

  int LinkedInService::popupHeight() const
  {
    return popupDialogHeight;
  }

  std::string LinkedInService::redirectEndpoint() const
  {
    return configurationProperty(RedirectEndpointProperty);
  }

  std::string LinkedInService::authorizationEndpoint() const
  {
    return AuthUrl;
  }

  std::string LinkedInService::tokenEndpoint() const
  {
    return TokenUrl;
  }

  std::string LinkedInService::clientId() const
  {
    return configurationProperty(ClientIdProperty);
  }

  std::string LinkedInService::clientSecret() const
  {
    return configurationProperty(ClientSecretProperty);
  }

  Http::Method LinkedInService::tokenRequestMethod() const
  {
    return Http::Post;
  }

  OAuthProcess *LinkedInService::createProcess(const std::string& scope) const
  {
    return new LinkedInProcess(*this, scope, getUserProfileAsJson);
  }

}}
