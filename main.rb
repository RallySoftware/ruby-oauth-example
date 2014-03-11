require 'sinatra'
require 'rest_client'

require 'net/http'
require 'securerandom'
require 'json'

RestClient.log = $stdout

# You can get your Client ID and Secret from
# https://login.rally1.rallydev.com/client.html
# The SERVER_URL must match the one specifed in Rally
CLIENT_ID  = ENV["CLIENT_ID"] 
CLIENT_SECRET = ENV["CLIENT_SECRET"] 
SERVER_URL = ENV["SERVER_URL"] 

# The Rally OAuth Server
OAUTH_SERVER = "https://rally1.rallydev.com/login/oauth2"

# Redirect to the auth URL to grant access
RALLY_AUTH_URL = OAUTH_SERVER + "/auth"

# Exchange the supplied code for an access token
RALLY_TOKEN_URL = OAUTH_SERVER + "/token"

# we will look up stories using this URL
RALLY_WSAPI_STORIES_URL = "https://rally1.rallydev.com/slm/webservice/v2.x/hierarchicalrequirement"
RALLY_WSAPI_USER_URL = "https://rally1.rallydev.com/slm/webservice/v2.x/user"

enable :sessions

get '/login' do
	uri = URI(RALLY_AUTH_URL)
	params = { 
		:state => SecureRandom.uuid,
		:response_type => "code",
		:redirect_uri => SERVER_URL + "/oauth-redirect",
		:client_id => CLIENT_ID,
		:scope => "openid"
	}
	session[:state] = params[:state]

	uri.query = URI.encode_www_form(params) 
	redirect to(uri.to_s) 
end


get '/oauth-redirect' do
	if params[:state] != session[:state]
		return "Invalid State"
	elsif params[:error] != nil
		return "Error with authorization #{params[:error]}"
	end

	new_params = { 
		:code => params[:code],
		:redirect_uri => SERVER_URL + "/oauth-redirect",
		:grant_type => "authorization_code",
		:client_id => CLIENT_ID,
		:client_secret => CLIENT_SECRET

	}
	
	# post to RALLY_TOKEN_URL, the body is form-urlencoded 
	# the client id and secret can also be sent as basic-auth
	begin 
		access_resp = RestClient.post RALLY_TOKEN_URL, URI.encode_www_form(new_params), :content_type => "application/x-www-form-urlencoded", :accept => :json
	rescue Exception => e
		return "Failed to get Token #{e}"
	end
	
	session[:auth] = JSON.load(access_resp)["access_token"]
	session[:state] = nil
	
	redirect to('/') 
end


get '/' do
	if session[:auth].nil? 
		redirect to('/login')
	end
	user_stories = []

	# Lookup our username
	user_resp = JSON.load(RestClient.get RALLY_WSAPI_USER_URL,  { "zsessionid" => session[:auth] })
	username = user_resp["User"]["UserName"]
	# Lookup the stories for whichever user we are authenticated as
	wsapi_resp = JSON.load(RestClient.get RALLY_WSAPI_STORIES_URL,  { "zsessionid" => session[:auth], :params => { :fetch => "Name", :query => "(Owner = #{user_resp["User"]["UserName"]})" }})
	wsapi_resp["QueryResult"]["Results"].each { | user_story |
		user_stories << user_story
	}
	erb :index, :locals => { :user_stories => user_stories, :username => username }
end

get '/logout' do
	session[:auth] = nil
	"Logged Out"
end

