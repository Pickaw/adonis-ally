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
 * TikTok driver to authenticating users via OAuth2Scheme.
 *
 * @class TikTok
 * @constructor
 */
class TikTok extends OAuth2Scheme {
  constructor (Config) {
    const config = Config.get('services.ally.tiktok')

    utils.validateDriverConfig('tiktok', config)
    utils.debug('tiktok', config)

    super(config.clientId, config.clientSecret, config.headers)

    /**
     * Oauth specific values to be used when creating the redirect
     * url or fetching user profile.
     */
    this._clientId = config.clientId
    this._clientSecret = config.clientSecret
    this._redirectUri = config.redirectUri
    this._redirectUriOptions = _.merge({ response_type: 'code' }, config.options)

    this.scope = _.size(config.scope) ? config.scope : ['user.info.basic', 'user.info.username']
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
    return `https://www.tiktok.com/v2/auth/authorize`
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
    return 'https://business-api.tiktok.com/open_api/v1.3/tt_user/oauth2/token/'
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
    const profileUrl = `https://business-api.tiktok.com/open_api/v1.3/business/get/?business_id=${accessTokenResponse.result.data.open_id}&fields=["username", "display_name", "profile_image", "followers_count"]`

    const response = await got(profileUrl, {
      headers: {
        'Content-Type': 'application/json',
        'Access-Token': accessTokenResponse.accessToken,
      },
      json: true
    })

    return response.body
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
    const expires = _.get(accessTokenResponse, 'result.expires_in')


    user.setOriginal(userProfile)
      .setFields(
        accessTokenResponse.result.data.open_id,
        userProfile.data.name,
        null,
        userProfile.data.display_name,
        userProfile.data.profile_picture
      )
      .setToken(
        accessTokenResponse.accessToken,
        accessTokenResponse.refreshToken,
        null,
        expires ? Number(expires) : null
      )
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
   * Parses the redirect errors returned by tiktok
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

    const accessTokenResponse = await this.getAccessToken(code, this._redirectUri, {
      grant_type: 'authorization_code',
      headers: {
        'Content-Type': 'application/json'
      }
    })

    const userProfile = await this._getUserProfile(accessTokenResponse)
    return this._buildAllyUser(userProfile, accessTokenResponse)
  }

  /**
   *
   * @param {string} accessToken
   */
  async getUserByToken (accessToken) {
    const userProfile = await this._getUserProfile(accessToken)

    return this._buildAllyUser(userProfile, { accessToken, refreshToken: null })
  }
}

module.exports = TikTok
