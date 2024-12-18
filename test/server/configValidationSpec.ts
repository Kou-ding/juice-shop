import chai = require('chai')
import sinonChai = require('sinon-chai')
import validateConfig from '../../lib/startup/validateConfig'

const expect = chai.expect
chai.use(sinonChai)

const { checkUnambiguousMandatorySpecialProducts, checkUniqueSpecialOnProducts, checkYamlSchema, checkMinimumRequiredNumberOfProducts, checkUnambiguousMandatorySpecialMemories, checkMinimumRequiredNumberOfMemories, checkUniqueSpecialOnMemories, checkSpecialMemoriesHaveNoUserAssociated, checkNecessaryExtraKeysOnSpecialProducts } = require('../../lib/startup/validateConfig')

// Helper function to generate a valid list of products
const generateValidProducts = () => [
  { name: 'Apple Juice', useForChristmasSpecialChallenge: true },
  { name: 'Orange Juice', urlForProductTamperingChallenge: 'foobar' },
  { name: 'Melon Juice', fileForRetrieveBlueprintChallenge: 'foobar', exifForBlueprintChallenge: ['OpenSCAD'] },
  { name: 'Rippertuer Special Juice', keywordsForPastebinDataLeakChallenge: ['bla', 'blubb'] }
]

// Helper function to generate an invalid list of products (with missing or duplicated challenges)
const generateInvalidProducts = () => [
  { name: 'Apple Juice', useForChristmasSpecialChallenge: true },
  { name: 'Melon Bike', useForChristmasSpecialChallenge: true },
  { name: 'Orange Juice', urlForProductTamperingChallenge: 'foobar' },
  { name: 'Melon Juice', fileForRetrieveBlueprintChallenge: 'foobar', exifForBlueprintChallenge: ['OpenSCAD'] }
]

// Helper function to generate valid memories
const generateValidMemories = () => [
  { image: 'bla.png', geoStalkingMetaSecurityQuestion: 42, geoStalkingMetaSecurityAnswer: 'foobar' },
  { image: 'blubb.png', geoStalkingVisualSecurityQuestion: 43, geoStalkingVisualSecurityAnswer: 'barfoo' }
]

// Helper function to generate invalid memories (with mixed challenge keys)
const generateInvalidMemories = () => [
  { image: 'bla.png', geoStalkingMetaSecurityQuestion: 42, geoStalkingVisualSecurityAnswer: 'foobar' },
  { image: 'blubb.png', geoStalkingVisualSecurityQuestion: 43, geoStalkingMetaSecurityAnswer: 'barfoo' }
]

describe('configValidation', () => {
  describe('checkUnambiguousMandatorySpecialProducts', () => {
    it('should accept a valid config', () => {
      expect(checkUnambiguousMandatorySpecialProducts(generateValidProducts())).to.equal(true)
    })

    it('should fail if multiple products are configured for the same challenge', () => {
      expect(checkUnambiguousMandatorySpecialProducts(generateInvalidProducts())).to.equal(false)
    })

    it('should fail if a required challenge product is missing', () => {
      const products = [{ name: 'Apple Juice', useForChristmasSpecialChallenge: true }, { name: 'Orange Juice', urlForProductTamperingChallenge: 'foobar' }]
      expect(checkUnambiguousMandatorySpecialProducts(products)).to.equal(false)
    })
  })

  describe('checkNecessaryExtraKeysOnSpecialProducts', () => {
    it('should accept a valid config', () => {
      expect(checkNecessaryExtraKeysOnSpecialProducts(generateValidProducts())).to.equal(true)
    })

    it('should fail if product has no exifForBlueprintChallenge', () => {
      const products = [{ name: 'Apple Juice', useForChristmasSpecialChallenge: true }, { name: 'Orange Juice', urlForProductTamperingChallenge: 'foobar' }, { name: 'Melon Juice', fileForRetrieveBlueprintChallenge: 'foobar' }]
      expect(checkNecessaryExtraKeysOnSpecialProducts(products)).to.equal(false)
    })
  })

  describe('checkUniqueSpecialOnProducts', () => {
    it('should accept a valid config', () => {
      expect(checkUniqueSpecialOnProducts(generateValidProducts())).to.equal(true)
    })

    it('should fail if a product is configured for multiple challenges', () => {
      const products = [{ name: 'Apple Juice', useForChristmasSpecialChallenge: true, urlForProductTamperingChallenge: 'foobar' }]
      expect(checkUniqueSpecialOnProducts(products)).to.equal(false)
    })
  })

  describe('checkMinimumRequiredNumberOfProducts', () => {
    it('should accept a valid config', () => {
      const products = [{ name: 'Apple Juice' }, { name: 'Orange Juice' }, { name: 'Melon Juice' }, { name: 'Rippertuer Special Juice' }]
      expect(checkMinimumRequiredNumberOfProducts(products)).to.equal(true)
    })

    it('should fail if less than 4 products are configured', () => {
      const products = [{ name: 'Apple Juice' }, { name: 'Orange Juice' }, { name: 'Melon Juice' }]
      expect(checkMinimumRequiredNumberOfProducts(products)).to.equal(false)
    })
  })

  describe('checkUnambiguousMandatorySpecialMemories', () => {
    it('should accept a valid config', () => {
      expect(checkUnambiguousMandatorySpecialMemories(generateValidMemories())).to.equal(true)
    })

    it('should fail if multiple memories are configured for the same challenge', () => {
      const memories = [{ image: 'bla.png', geoStalkingMetaSecurityQuestion: 42, geoStalkingMetaSecurityAnswer: 'foobar' }, { image: 'blubb.png', geoStalkingVisualSecurityQuestion: 43, geoStalkingVisualSecurityAnswer: 'barfoo' }, { image: 'lalala.png', geoStalkingMetaSecurityQuestion: 46, geoStalkingMetaSecurityAnswer: 'foobarfoo' }]
      expect(checkUnambiguousMandatorySpecialMemories(memories)).to.equal(false)
    })

    it('should fail if a required challenge memory is missing', () => {
      const memories = [{ image: 'bla.png', geoStalkingMetaSecurityQuestion: 42, geoStalkingMetaSecurityAnswer: 'foobar' }]
      expect(checkUnambiguousMandatorySpecialMemories(memories)).to.equal(false)
    })

    it('should fail if memories have mixed up the required challenge keys', () => {
      expect(checkUnambiguousMandatorySpecialMemories(generateInvalidMemories())).to.equal(false)
    })
  })

  describe('checkMinimumRequiredNumberOfMemories', () => {
    it('should accept a valid config', () => {
      const memories = [{ image: 'bla.png', user: 'admin' }, { image: 'blubb.png', user: 'bjoern' }]
      expect(checkMinimumRequiredNumberOfMemories(memories)).to.equal(true)
    })

    it('should fail if less than 2 memories are configured', () => {
      const memories = [{ image: 'bla.png', user: 'admin' }]
      expect(checkMinimumRequiredNumberOfMemories(memories)).to.equal(false)
    })
  })

  it(`should accept the active config from config/${process.env.NODE_ENV}.yml`, async () => {
    expect(await validateConfig({ exitOnFailure: false })).to.equal(true)
  })

  it('should fail if the config is invalid', async () => {
    expect(await validateConfig({ products: [], exitOnFailure: false })).to.equal(false)
  })

  it('should accept a config with valid schema', () => {
    const config = { application: { domain: 'juice-b.ox', name: 'OWASP Juice Box', welcomeBanner: { showOnFirstStart: false } }, hackingInstructor: { avatarImage: 'juicyEvilWasp.png' } }
    expect(checkYamlSchema(config)).to.equal(true)
  })

  it('should fail for a config with schema errors', () => {
    const config = { application: { domain: 42, id: 'OWASP Juice Box', welcomeBanner: { showOnFirstStart: 'yes' } }, hackingInstructor: { avatarImage: true } }
    expect(checkYamlSchema(config)).to.equal(false)
  })
})
