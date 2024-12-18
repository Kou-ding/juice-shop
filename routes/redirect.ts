module.exports = function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string
    const thirdPartyUrls = [
      'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
      'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
      'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
    ]
    
    // Check if the URL is allowed for redirection
    if (security.isRedirectAllowed(toUrl)) {
      // Solve challenges if applicable
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
        return thirdPartyUrls.includes(toUrl)
      })
      challengeUtils.solveIf(challenges.redirectChallenge, () => {
        return isUnintendedRedirect(toUrl)
      })

      // Check if the URL is from a third-party and warn the user
      if (thirdPartyUrls.includes(toUrl)) {
        // Send a warning message before redirecting
        return res.render('warningPage', {
          message: `You are being redirected to a third-party website: ${toUrl}. Please proceed with caution.`
        })
      }

      // Proceed with redirect
      res.redirect(toUrl)
    } else {
      // Handle unrecognized target URL
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}
