import {
  BinaryLike,
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scrypt,
} from 'crypto'
import { IKeyStore } from './dataEncryption.js'

/**
 * A generic interface representing a async return
 * of data, could be to fetch a salt value, could
 * be to fetch a password etc
 */
export interface IKeyStoreValueProvider {
  /**
   * @returns {Promise<Buffer>} when invoked asynchronously returns a value
   */
  (): Promise<Buffer>
}
/**
 * A interface describing the contract for
 * providing context data for AAED encryption
 */
export interface IKeyStoreContextProvider {
  /**
   * Provided some unique identifier, asynchronously
   * return a buffer for the relevant context data
   * to use in AAED encryption
   */
  (id: string): Promise<Buffer>
}

/**
 * A base class for a data encryption key store,
 * data encryption keys are sealed at rest with a root key.
 * This class delegates the storage details to child classes and
 * takes on the unsealing/sealing responsibilities
 */
export abstract class BaseKeyStore implements IKeyStore {
  protected readonly keyStorePasswordProvider: IKeyStoreValueProvider
  protected readonly keyStoreSaltProvider: IKeyStoreValueProvider
  protected readonly keyStoreContextProvider: IKeyStoreContextProvider

  /**
   *
   * @param  {IKeyStoreValueProvidier} keyStorePasswordProvider when invoked resolves with the password value used to generate key with scrypt to seal root keys
   * @param  {IKeyStoreValueProvidier} keyStoreSaltProvider when invokved resolves with a salt value used with scrypt and the password to seal root keys
   * @param {IKeyStoreContextProvider} keyStoreContextProvider when invoked resolves with a appropriate context value for AAED on a data encryption key
   */
  constructor(
    keyStorePasswordProvider: IKeyStoreValueProvider,
    keyStoreSaltProvider: IKeyStoreValueProvider,
    keyStoreContextProvider: IKeyStoreContextProvider
  ) {
    this.keyStorePasswordProvider = keyStorePasswordProvider
    this.keyStoreSaltProvider = keyStoreSaltProvider
    this.keyStoreContextProvider = keyStoreContextProvider
  }

  /**
   * Check if the root key id specified exists in the store
   *
   * @param {string} rootKeyId unique identifier of a root key
   * @returns {Promise<boolean>} resolves true if the root key exists in the store, false otherwise
   */
  async hasSealedRootKey(rootKeyId: string): Promise<boolean> {
    const keySlot = await this.getKeySlot(
      'dek',
      rootKeyId,
      await this.keyStoreSaltProvider()
    )
    return this.hasKeyInSlot(keySlot)
  }

  /**
   * Save a sealed root key to the backing store, root
   * keys are sealed by a master key
   * @param {string} rootKeyId unique identifier of root key
   * @param {Buffer} key root key
   */
  async saveSealedRootKey(rootKeyId: string, key: Buffer): Promise<void> {
    await this.saveSealedKey('root', rootKeyId, key)
  }

  /**
   * A data encryption key is sealed by a root key
   * @param {string} keyId unique identifier of a data encryption key
   * @param {Buffer} key data encryption key
   */
  async saveSealedDataEncKey(keyId: string, key: Buffer): Promise<void> {
    await this.saveSealedKey('dek', keyId, key)
  }

  /**
   * Check if a data encryption key exists in the store
   * @param {string} keyId unique data encryption key
   * @returns {Promise<boolean>} resolves true if the specified data encryption key exists in the store
   */
  async hasSealedDataEncKey(keyId: string): Promise<boolean> {
    const keySlot = await this.getKeySlot(
      'dek',
      keyId,
      await this.keyStoreSaltProvider()
    )
    return this.hasKeyInSlot(keySlot)
  }

  /**
   * Fetches the specified root key from the store and returns the unsealed value
   * @param {string} rootKeyId identifier of root key
   * @returns {Promise<Buffer>} root key
   */
  fetchSealedRootKey(rootKeyId: string): Promise<Buffer> {
    return this.fetchSealedKey('root', rootKeyId)
  }

  /**
   * Fetches the specified data encryption key from the store and returns the unsealed value
   * @param {string} keyId unique id of the data encryption key
   * @returns {Promise<Buffer>} data encryption key
   */
  fetchSealedDataEncKey(keyId: string): Promise<Buffer> {
    return this.fetchSealedKey('dek', keyId)
  }

  /**
   * Remove a root key from the underlying key store
   * @param {string} rootKeyId unique id of the root key
   * @returns {Promise<void>} resolves when delete is complete
   */
  async destroySealedRootKey(rootKeyId: string): Promise<void> {
    await this.deleteSealedKey('root', rootKeyId)
  }

  /**
   * Destroy a sealed data encryption key by removing it from the underlying store
   * @param {string} keyId unique id of the data encryption key
   * @returns {Promise<void>} resolves when the delete operation is complete
   */
  async destroySealedDataEncKey(keyId: string): Promise<void> {
    await this.deleteSealedKey('dek', keyId)
  }

  /**
   * Destroys all keys in the store
   * @returns {Promise<void>} resolves when all keys have been removed from the key store
   */
  async destroyAllKeys(): Promise<void> {
    await this.clearKeySlots()
  }

  /**
   * Return a key generated from the password, salt and associated with the provided
   * context generated by scrypt
   * @param {BinaryLike} password password to feed into scrypt
   * @param {BinaryLine} salt salt to feed into scrypt
   * @param {BinaryLike} context context of the usage, not yet used
   * @returns {Promise<Buffer>} resolves with result of scrypt operation
   */
  protected async getScryptKey(
    password: BinaryLike,
    salt: BinaryLike,
    context: Buffer
  ): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      scrypt(password, salt, 32, (err, key) => {
        if (err) {
          return reject(err)
        }
        return resolve(key)
      })
    })
  }

  /**
   * Determine a unique key slot
   * @param {string} type type of key
   * @param {string} keyId unique key id
   * @param {Buffer} salt salt/nonce
   * @returns {Promise<string>} unique key slot to place the key
   */
  protected async getKeySlot(
    type: string,
    keyId: string,
    salt: Buffer
  ): Promise<string> {
    const hash = createHash('sha256')
    hash.update(type)
    hash.update(keyId)
    hash.update(salt)
    return hash.digest('hex')
  }

  /**
   * Save and seal a key
   * @param {string} type type of key
   * @param {string} keyId unique key identifier
   * @param {Buffer} key key
   * @returns {Promise<void>} resolves when sealed ans persisted to key store
   */
  protected async saveSealedKey(
    type: string,
    keyId: string,
    key: Buffer
  ): Promise<void> {
    // first lets get the file name which is sha256(key id + salt)
    const salt = await this.keyStoreSaltProvider()
    const keySlot = await this.getKeySlot(type, keyId, salt)
    const context = await this.keyStoreContextProvider(keyId)
    const password = await this.keyStorePasswordProvider()
    const scryptKey = await this.getScryptKey(password, salt, context)
    const iv = randomBytes(16)
    const cipher = createCipheriv('aes-256-gcm', scryptKey, iv, {
      authTagLength: 16,
    }).setAAD(context)
    const ciphertext = Buffer.concat([
      iv,
      cipher.update(key),
      cipher.final(),
      cipher.getAuthTag(),
    ])
    await this.putKeyInSlot(keySlot, ciphertext)
  }

  /**
   * Fetch a key from the store and unseal it for usage.
   * @param {string} type type of key
   * @param {string} keyId unique key id
   * @returns {Promise<Buffer>} resolves with unsealed key
   */
  protected async fetchSealedKey(type: string, keyId: string): Promise<Buffer> {
    const salt = await this.keyStoreSaltProvider()
    const keySlot = await this.getKeySlot(type, keyId, salt)
    if (!(await this.hasKeyInSlot(keySlot))) {
      throw new Error('Key not found')
    }
    const key = await this.getKeyInSlot(keySlot)
    const context = await this.keyStoreContextProvider(keyId)
    const password = await this.keyStorePasswordProvider()
    const scryptKey = await this.getScryptKey(password, salt, context)
    const iv = key.slice(0, 16)
    const authTag = key.slice(key.length - 16)
    const keyCipherText = key.slice(16, key.length - 16)
    const decipher = createDecipheriv('aes-256-gcm', scryptKey, iv, {
      authTagLength: 16,
    }).setAAD(context)
    decipher.setAuthTag(authTag)
    return Buffer.concat([decipher.update(keyCipherText), decipher.final()])
  }

  /**
   * Delete a sealed key from the key store
   * @param {string} type type of key
   * @param {string} keyId unique key id
   * @returns {Promise<void>} resolves when delete is complete
   */
  protected async deleteSealedKey(type: string, keyId: string): Promise<void> {
    const salt = await this.keyStoreSaltProvider()
    const keySlot = await this.getKeySlot(type, keyId, salt)
    await this.deleteKeySlot(keySlot)
  }

  /**
   * Stores the key in the specified slot in the backing store
   * @param {string} keySlot unique key slot
   * @param {Buffer} key key
   * @returns {Promise<void>} resolves when key has been comitted to the store
   */
  protected abstract putKeyInSlot(keySlot: string, key: Buffer): Promise<void>

  /**
   * Get the sealed key in the specified slot
   * @param {string} keySlot Unique key slot
   * @returns {Promise<void>} resolves with sealed key value
   */
  protected abstract getKeyInSlot(keySlot: string): Promise<Buffer>

  /**
   * Check if a key slot has a value
   * @param {string} keySlot unique key slot
   * @returns {Promise<boolean} reoslves true if the store has a value in the specified key slot
   */
  protected abstract hasKeyInSlot(keySlot: string): Promise<boolean>

  /**
   * Delete a specified key slot
   * @param {string} keySlot unique key slot
   * @returns {Promise<void>} resolves when the value in the key slot has been removed
   */
  protected abstract deleteKeySlot(keySlot: string): Promise<void>

  /**
   * Remove all values in all key slots
   * @returns {Promise<void>} resolves when all key slots have been erased
   */
  protected abstract clearKeySlots(): Promise<void>

  /**
   * Cleanup any resources/connections used by the key store
   * @returns {Promise<void>} resolves when close operation is complete
   */
  public abstract close(): Promise<void>
}
