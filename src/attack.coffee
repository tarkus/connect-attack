STATUS_THROTTLED = 429
STATUS_BANNED = 504

extend = (dest, objs...) ->
  for obj in objs
    dest[k] = v for k, v of obj
  dest

get_ip = (req) ->
  if req.headers['x-forwarded-for']?
    ips = req.headers['x-forwarded-for'].split /, /
    ips[0]
  else
    req.connection.remoteAddress

module.exports = exports = (rules = {}, options = {}) ->
  return connect_attack if connect_attack
  connect_attack = module.exports.instance = new ConnectAttack rules, options

class ConnectAttack

  constructor: (options = {}) ->
    @options = extend {
      store: null
      error_pages: null
    }, options

    @whitelists = {}
    @blacklists = {}
    @throttles  = {}
    @cache = {}

  whitelist: ->
    rules = {}
    if arguments.length > 1
      name = arguments[0]
      discriminator = arguments[1]
      rules[name] = discriminator
    else if typeof arguments[0] is 'object'
      rules = arguments
    @whitelists[n] = d for n, d of rules
    @

  blacklist: ->
    rules = {}
    if arguments.length > 1
      name = arguments[0]
      discriminator = arguments[1]
      rules[name] = discriminator
    else if typeof arguments[0] is 'object'
      rules = arguments
    @blacklists[n] = d for n, d of rules
    @

  throttle: ->
    rules = {}
    if arguments.length == 3
      name = arguments[0]
      options = arguments[1]
      discriminator = arguments[2]
      rules[name] =
        options: extend {
          limit: 5
          period: 60
          bantime: null
        }, options
        discriminator: discriminator
    else if typeof arguments[0] is 'object'
      rules = arguments[0]
    @throttles[name] = detail for name, detail of rules
    @

  check: (req, res, next) ->
    @stats =
      count: 0
      expiring: null
      throttled: false
      banned: false
    if @whilelisted req
      next()
    else if @blacklisted req
      @blacklisted_response(req, res, next)
    else if @throttled req
      @throttled_response(req, res, next)
    else
      next()

  middleware: ->
    (req, res, next) =>
      req.ip = get_ip(req)
      @check(req, res, next)

  whilelisted: (req) ->
    for name, discriminator of @whitelists
      matched = discriminator(req)
      return matched if matched

  blacklisted: (req) ->
    for name, discriminator of @blacklists
      matched = discriminator(req)
      return matched if matched

  throttled: (req) ->
    for name, detail of @throttles
      matched = detail.discriminator(req)
      continue unless matched
      @count(req, name, detail.options)
      return matched if @stats.throttled

  blacklisted_response: (req, res) ->
    res.statusCode = STATUS_BANNED
    return res.end() unless @options.error_pages[res.statusCode]
    res.write @options.error_pages[res.statusCode]
    res.end()

  throttled_response: (req, res) ->
    if @stats.banned
      console.log "Client #{req.ip} banned from #{req.url}"
      res.statusCode = STATUS_BANNED
    else
      console.log "Client #{req.ip} reaches rate limit on #{req.url}"
      res.statusCode = STATUS_THROTTLED
    
    return res.end() unless @options.error_pages[res.statusCode]
    res.write @options.error_pages[res.statusCode]
    res.end()

  count: (req, name, options) ->
    counter_key = "#{req.ip}|#{name}|#{req.url}|counter"
    expiring_key = "#{req.ip}|#{name}|#{req.url}|expiring"

    unless @options.store?
      now = Math.round(new Date().getTime() / 1000)

      unless @cache[counter_key]? and @cache[expiring_key] > now
        @stats.count = 1
        @stats.expiring = now + options.period
        @cache[counter_key] = @stats.count
        @cache[expiring_key] = @stats.expiring
        return @stats

      @cache[counter_key] += 1
      if @cache[counter_key] > options.limit
        @stats.throttled = true
        if options.bantime > 0
          @cache[expiring_key] + options.bantime
          @stats.banned = true

      @stats.count = @cache[counter_key]
      @stats.expiring = @cache[expiring_key]

    @stats

  clear_cache: ->
    @cache = {}
