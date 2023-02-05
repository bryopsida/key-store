import { IUsableClosable } from './using.js'

export interface IKeyStore extends IUsableClosable {
  saveSealedRootKey(rootKeyId: string, key: Buffer): Promise<void>
  saveSealedDataEncKey(keyId: string, key: Buffer): Promise<void>
  hasSealedRootKey(rootKeyId: string): Promise<boolean>
  hasSealedDataEncKey(keyId: string): Promise<boolean>
  fetchSealedRootKey(rootKeyId: string): Promise<Buffer>
  fetchSealedDataEncKey(keyId: string): Promise<Buffer>
  destroySealedRootKey(rootKeyId: string): Promise<void>
  destroySealedDataEncKey(keyId: string): Promise<void>
  destroyAllKeys(): Promise<void>
}
