'use strict'

/*
 * adonis-ally
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const got = require('got')

const CE = require('../Exceptions')
const OAuth2Scheme = require('../Schemes/OAuth2')
const AllyUser = require('../AllyUser')
const utils = require('../../lib/utils')
const _ = require('lodash')

/**
 * Threads driver to authenticating users via OAuth2Scheme.
 *
 * @class Threads
 * @constructor
 */
class Threads extends OAuth2Scheme {
  constructor (Config) {
    const config = Config.get('services.ally.threads')

    utils.validateDriverConfig('threads', config)
    utils.debug('threads', config)

    super(config.clientId, config.clientSecret, config.headers)

    /**
     * Oauth specific values to be used when creating the redirect
     * url or fetching user profile.
     */
    this._clientId = config.clientId
    this._clientSecret = config.clientSecret
    this._redirectUri = config.redirectUri
    this._redirectUriOptions = _.merge({ response_type: 'code' }, config.options)

    this.scope = _.size(config.scope) ? config.scope : ['threads_basic']
  }

  /**
   * Injections to be made by the IoC container
   *
   * @attribute inject
   *
   * @return {Array}
   */
  static get inject () {
    return ['Adonis/Src/Config']
  }

  /**
   * Returns a boolean telling if driver supports
   * state
   *
   * @method supportStates
   *
   * @return {Boolean}
   */
  get supportStates () {
    return true
  }

  /**
   * Scope seperator for seperating multiple
   * scopes.
   *
   * @attribute scopeSeperator
   *
   * @return {String}
   */
  get scopeSeperator () {
    return ','
  }

  /**
   * Base url to be used for constructing
   * google oauth urls.
   *
   * @attribute baseUrl
   *
   * @return {String}
   */
  get baseUrl () {
    return ''
  }

  /**
   * Relative url to be used for redirecting
   * user.
   *
   * @attribute authorizeUrl
   *
   * @return {String} [description]
   */
  get authorizeUrl () {
    return `https://threads.net/oauth/authorize`
  }

  /**
   * Relative url to be used for exchanging
   * access token.
   *
   * @attribute accessTokenUrl
   *
   * @return {String}
   */
  get accessTokenUrl () {
    return 'https://graph.threads.net/oauth/access_token'
  }

  /**
   * Returns the user profile as an object using the
   * access token.
   *
   * @method _getUserProfile
   * @async
   *
   * @param   {String} accessToken
   *
   * @return  {Object}
   *
   * @private
   */
  async _getUserProfile (accessTokenResponse) {
    const profileUrl = `https://graph.threads.net/v1.0/me?fields=id,username,name,threads_profile_picture_url,threads_biography&access_token=${accessTokenResponse.accessToken}`

    const response = await got(profileUrl, {
      headers: {
        'Content-Type': 'application/json',
      },
      json: true
    })

    return response.body
  }

  /**
   * Exchange a short-lived access token for a long-lived token
   *
   * @method _exchangeForLongLivedToken
   * @async
   *
   * @param   {String} shortLivedToken
   *
   * @return  {Object}
   *
   * @private
   */
  async _exchangeForLongLivedToken (shortLivedToken) {
    const exchangeUrl = `https://graph.threads.net/access_token?grant_type=th_exchange_token&client_secret=${this._clientSecret}&access_token=${shortLivedToken}`

    const response = await got(exchangeUrl, {
      headers: {
        'Content-Type': 'application/json',
      },
      json: true
    })

    return {
      accessToken: response.body.access_token,
      tokenType: response.body.token_type,
      expiresIn: response.body.expires_in,
      expiresAt: new Date(Date.now() + (response.body.expires_in * 1000))
    }
  }

  /**
   * Refresh a long-lived access token
   *
   * @method refreshLongLivedToken
   * @async
   *
   * @param   {String} longLivedToken
   *
   * @return  {Object}
   *
   * @public
   */
  async refreshLongLivedToken (longLivedToken) {
    const refreshUrl = `https://graph.threads.net/refresh_access_token?grant_type=th_refresh_token&access_token=${longLivedToken}`

    const response = await got(refreshUrl, {
      headers: {
        'Content-Type': 'application/json',
      },
      json: true
    })

    return {
      accessToken: response.body.access_token,
      tokenType: response.body.token_type,
      expiresIn: response.body.expires_in,
      expiresAt: new Date(Date.now() + (response.body.expires_in * 1000))
    }
  }

  /**
   * Check if a token needs refresh (if it's older than 24 hours but not expired)
   *
   * @method shouldRefreshToken
   * @async
   *
   * @param   {Date} expiresAt
   *
   * @return  {Boolean}
   *
   * @public
   */
  shouldRefreshToken (expiresAt) {
    const now = new Date()
    const oneDayFromNow = new Date(now.getTime() + (24 * 60 * 60 * 1000))

    // Refresh if token expires within 24 hours
    return expiresAt <= oneDayFromNow && expiresAt > now
  }

  /**
   * Normalize the user profile response and build an Ally user.
   *
   * @param {object} userProfile
   * @param {object} accessTokenResponse
   *
   * @return {object}
   *
   * @private
   */
  _buildAllyUser (userProfile, accessTokenResponse) {

    const user = new AllyUser()

    user.setOriginal(userProfile)
      .setFields(
        userProfile.id,
        userProfile.username,
        null,
        userProfile.name,
        userProfile.threads_profile_picture_url
      )
      .setToken(
        accessTokenResponse.accessToken,
        null,
        null,
        accessTokenResponse.expiresIn || null
      )

    // Add additional token information for database storage
    user.tokenInfo = {
      expiresIn: accessTokenResponse.expiresIn,
      expiresAt: accessTokenResponse.expiresAt,
      tokenType: accessTokenResponse.tokenType || 'bearer'
    }

    return user
  }

  /**
   * Returns the redirect url for a given provider.
   *
   * @method getRedirectUrl
   *
   * @param {String} [state]
   *
   * @return {String}
   */
  async getRedirectUrl (state) {
    const options = state ? Object.assign(this._redirectUriOptions, { state }, { client_key: this._clientId }) : this._redirectUriOptions
    return this.getUrl(this._redirectUri, this.scope, options)
  }

  /**
   * Parses the redirect errors returned by threads
   * and returns the error message.
   *
   * @method parseRedirectError
   *
   * @param  {Object} queryParams
   *
   * @return {String}
   */
  parseRedirectError (queryParams) {
    return queryParams.error || 'Oauth failed during redirect'
  }

  /**
   * Returns the user profile with it's access token, refresh token
   * and token expiry.
   *
   * @method getUser
   * @param {String} [originalState]
   *
   * @return {Object}
   */
  async getUser (queryParams, originalState) {
    const code = queryParams.code
    const state = queryParams.state

    /**
     * Throw an exception when query string does not have
     * code.
     */
    if (!code) {
      const errorMessage = this.parseRedirectError(queryParams)
      throw CE.OAuthException.tokenExchangeException(errorMessage, null, errorMessage)
    }

    /**
     * Valid state with original state
     */
    if (state && originalState !== state) {
      throw CE.OAuthException.invalidState()
    }

    // Get short-lived token first
    const shortLivedTokenResponse = await this.getAccessToken(code, this._redirectUri, {
      grant_type: 'authorization_code',
      headers: {
        'Content-Type': 'application/json'
      }
    })

    // Exchange for long-lived token
    const longLivedTokenResponse = await this._exchangeForLongLivedToken(shortLivedTokenResponse.accessToken)

    const userProfile = await this._getUserProfile(longLivedTokenResponse)
    return this._buildAllyUser(userProfile, longLivedTokenResponse)
  }

  /**
   *
   * @param {string} accessToken
   */
  async getUserByToken (accessToken) {
    const userProfile = await this._getUserProfile({ accessToken })

    return this._buildAllyUser(userProfile, { accessToken, refreshToken: null })
  }
}

module.exports = Threads
