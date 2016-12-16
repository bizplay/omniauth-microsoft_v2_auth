# Omniauth::MicrosoftV2Auth

Microsoft V2 OAuth2 Strategy for OmniAuth.
Can be used to authenticate with Microsoft Services and get a token for the Microsoft Graph Api.

Since the original gem was only available as part of the [ruby-connect-rest-sample](https://github.com/microsoftgraph/ruby-connect-rest-sample), 
I extracted it into this stand-alone Gem. 

If you're having trouble getting everything to work (as I did), then you might find some 
usefull information in [my StackOverflow post on this topic](http://stackoverflow.com/questions/41119421/how-to-properly-register-and-access-office-365-graph-api-for-oauth2-using-omnia/41145716#41145716).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth-microsoft_v2_auth'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-microsoft_v2_auth

## Usage
The base usage looks like this:
```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :microsoft_v2_auth, ENV['OFFICE365_KEY'], ENV['OFFICE365_SECRET']
end
```

Here's an example where we request permissions to read a user's calendar, 
get a refresh_token (by setting it to offline_access) and be able to ready the 
user's profile:
```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :microsoft_v2_auth, ENV['OFFICE365_KEY'], ENV['OFFICE365_SECRET'], :scope => 'openid email profile offline_access https://graph.microsoft.com/User.Read https://graph.microsoft.com/Calendars.Read'
end
```