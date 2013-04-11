/** 
Open Bank Project - Transparency / Social Finance Web Application
Copyright (C) 2011, 2012, TESOBE / Music Pictures Ltd

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Email: contact@tesobe.com 
TESOBE / Music Pictures Ltd 
Osloerstrasse 16/17
Berlin 13359, Germany

  This product includes software developed at
  TESOBE (http://www.tesobe.com/)
  by 
  Simon Redfern : simon AT tesobe DOT com
  Stefan Bethge : stefan AT tesobe DOT com
  Everett Sochowski : everett AT tesobe DOT com
  Ayoub Benali: ayoub AT tesobe DOT com

 */

package code.lib

import net.liftweb.http.SessionVar
import net.liftweb.common.Box
import net.liftweb.common.Empty
import oauth.signpost.OAuthProvider
import oauth.signpost.basic.DefaultOAuthProvider
import net.liftweb.util.Props
import net.liftweb.http.S
import oauth.signpost.OAuthConsumer
import oauth.signpost.basic.DefaultOAuthConsumer
import net.liftweb.mapper.By
import net.liftweb.common.Full
import net.liftweb.util.Helpers

sealed trait Provider {
  val name : String
  
  val requestTokenUrl : String
  val accessTokenUrl : String
  val authorizeUrl : String
  
  /**
   * Can't do oAuthProvider = new DefaultOAuthProvider(requestTokenUrl, accessTokenUrl, authorizeUrl)
   * here as the Strings all evaluate at null at this point in object creation
   */
  val oAuthProvider : OAuthProvider
  
  val consumerKey : String
  val consumerSecret : String
}

object OBPDemo extends Provider {
  val name = "OBP-Demo"
    
  val baseUrl = Props.get("hostname", S.hostName)
  val requestTokenUrl = baseUrl + "/oauth/initiate"
  val accessTokenUrl = baseUrl + "/oauth/token"
  val authorizeUrl = baseUrl + "/oauth/authorize"
  
  val oAuthProvider : OAuthProvider = new DefaultOAuthProvider(requestTokenUrl, accessTokenUrl, authorizeUrl)
  
  val consumerKey = SofiAPITransition.sofiConsumer.key.get
  val consumerSecret = SofiAPITransition.sofiConsumer.secret.get
}

case class Consumer(consumerKey : String, consumerSecret : String) {
  val oAuthConsumer : OAuthConsumer = new DefaultOAuthConsumer(consumerKey, consumerSecret)
}

case class Credential(provider : Provider, consumer : OAuthConsumer)

object credentials extends SessionVar[List[Credential]](Nil)

/**
 * Until the Social Finance app and the API are fully split, the Social Finance app will in fact call
 * its own API functions which requires it be registered as a consumer. This object takes care of that.
 */
object SofiAPITransition {
  
  //At the moment developer email has to be unique for code.model.Consumers, which is probably not how it should be.
  //The end result is that we should search based on it.
  val sofiEmail = "socialfinance@tesobe.com"
  
  def getOrCreateSofiConsumer : code.model.Consumer = {
    code.model.Consumer.find(By(code.model.Consumer.developerEmail, sofiEmail)) match {
      case Full(c) => c
      case _ => {
        code.model.Consumer.create.name("Social Finance").
        	appType(code.model.AppType.Web).description("").developerEmail(sofiEmail).isActive(true).
        	key(Helpers.randomString(40).toLowerCase).secret(Helpers.randomString(40).toLowerCase).saveMe()
      }
    }
  }
  
  val sofiConsumer = getOrCreateSofiConsumer
}

object OAuthClient {

  val defaultProvider = OBPDemo
  
  def getOrCreateCredential(provider : Provider) : Credential = {
    credentials.find(_.provider == provider) match {
      case Some(c) => c
      case None => {
        val consumer = new DefaultOAuthConsumer(provider.consumerKey, provider.consumerSecret)
        val credential = Credential(provider, consumer)
        credentials.set(credential :: credentials.get)
        credential
      }
    }
  }
		  						 
  def getAuthUrl(provider : Provider) : String = {
    val credential = getOrCreateCredential(provider)
    provider.oAuthProvider.retrieveRequestToken(credential.consumer, Props.get("hostname", S.hostName))
  }
  
}