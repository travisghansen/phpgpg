<?php
namespace PhpGpg\Tests\Unit;

class KeyTest extends \PHPUnit_Framework_TestCase
{
    public function testImportPublicKey()
    {
        global $resource_tmp;
        $resource = $resource_tmp;
        $resource->importKey(file_get_contents(NVIDIA_PUB_FILE));
        $keys = $resource->getKeys(NVIDIA_ID);

        $this->assertEquals(1, count($keys));

        $resource->importKey(file_get_contents(PERCONA_PUB_FILE));
        $resource->importKey(file_get_contents(MYSQL_PUB_FILE));
        $resource->importKey(file_get_contents(TEST1_PUB_FILE));
        $keys = $resource->getKeys();

        $this->assertEquals(4, count($keys));
    }
    
    public function testImportPrivateKeyWithPassphrase()
    {
        global $resource_tmp;
        $resource = $resource_tmp;
        $resource->importKey(file_get_contents(TEST3_SEC_FILE));
        $keys = $resource->getKeys();

        $this->assertEquals(5, count($keys));
        
        $data = $resource->addDecryptKey(TEST3_ID);
        $this->assertEquals(true, $data);
    }
 
    public function testCanEncrypt()
    {
        global $resource_tmp;
        $resource = $resource_tmp;
        $resource->addEncryptKey(TEST1_ID);
        $key = $resource->getKeys(TEST1_ID);
        $key = $key[0];
        $data = $key->canEncrypt();

        $this->assertEquals(true, $data);
    }
    
    public function testCanSign()
    {
        global $resource_1;
        $resource = $resource_1;
        $resource->importKey(file_get_contents(TEST1_SEC_FILE));
        $key = $resource->getKeys(TEST1_ID);
        $key = $key[0];
        $data = $key->canSign();

        $this->assertEquals(true, $data);
    }

    public function testEncrypt()
    {
        global $resource_tmp;
        $resource = $resource_tmp;
        $resource->enableArmor();
        $resource->addEncryptKey(TEST1_ID);
        $data = $resource->encrypt("test");

        $this->assertNotEquals(false, $data);
    }

    public function testEncryptDecrypt()
    {
        global $resource_tmp;
        global $resource_1;
        $resource_2 = $resource_tmp;
        $resource_2->enableArmor();
        $resource_2->importKey(file_get_contents(TEST1_PUB_FILE));
        $resource_2->addEncryptKey(TEST1_ID);
        $data = $resource_2->encrypt("test");

        $resource_1->enableArmor();
        $resource_1->importKey(file_get_contents(TEST1_SEC_FILE));
        $resource_1->addDecryptKey(TEST1_ID);
        $data = $resource_1->decrypt($data);

        $this->assertEquals("test", $data);
    }
    
    public function testEncryptDecryptPassphrase()
    {
        global $resource_tmp;
        global $resource_1;
        $resource_2 = $resource_tmp;
        $resource_2->enableArmor();
        $resource_2->importKey(file_get_contents(TEST3_PUB_FILE));
        $resource_2->addEncryptKey(TEST1_ID);
        $data = $resource_2->encrypt("test");

        return;
        $resource_1->enableArmor();
        $resource_1->importKey(file_get_contents(TEST3_SEC_FILE));
        $resource_1->addDecryptKey(TEST3_ID, TEST3_PASSPHRASE);
        $data = $resource_1->decrypt($data);

        $this->assertEquals("test", $data);
    }

    public function testEncryptSignDecryptVerify()
    {
        global $resource_1;
        global $resource_2;

        $resource_1->enableArmor();
        $resource_1->importKey(file_get_contents(TEST2_PUB_FILE));
        $resource_1->addEncryptKey(TEST2_ID);
        $resource_1->addSignKey(TEST1_ID);
        $data = $resource_1->encryptAndSign("test");

        $resource_2->enableArmor();
        $resource_2->importKey(file_get_contents(TEST1_PUB_FILE));
        $resource_2->importKey(file_get_contents(TEST2_SEC_FILE));
        $resource_2->addDecryptKey(TEST2_ID);
        $data = $resource_2->decryptAndVerify($data);

        $this->assertEquals("test", $data->getData());
    }

    public function testEncryptSignDecrypt()
    {
        global $resource_1;
        global $resource_2;

        $resource_1->enableArmor();
        $resource_1->importKey(file_get_contents(TEST2_PUB_FILE));
        $resource_1->addEncryptKey(TEST2_ID);
        $resource_1->addSignKey(TEST1_ID);
        $data = $resource_1->encryptAndSign("test");

        $resource_2->enableArmor();
        $resource_2->importKey(file_get_contents(TEST1_PUB_FILE));
        $resource_2->addDecryptKey(TEST2_ID);
        $data = $resource_2->decrypt($data);

        $this->assertEquals("test", $data);
    }

    public function testModels()
    {
        global $resource_1;
        $keys = $resource_1->getKeys(TEST1_ID);
        $key = $keys[0];
        $subKeys = $key->getSubKeys();
        $subKey = $subKeys[0];
        $userIds = $key->getUserIds();
        $userId = $userIds[0];

        $this->assertEquals("PhpGpg Test", $userId->getName());
        $this->assertEquals("", $userId->getComment());
        $this->assertEquals("test@email.com", $userId->getEmail());
        $this->assertEquals("PhpGpg Test <test@email.com>", $userId->getUid());
        $this->assertEquals(false, $userId->getIsRevoked());
        $this->assertEquals(true, $userId->getIsValid());

        $this->assertEquals('8B00BA3437CFA307', $subKey->getId());
        $this->assertEquals('04348505831EADAFE760BCF58B00BA3437CFA307', $subKey->getFingerprint());
        $this->assertEquals('1423980502', $subKey->getCreationDate());
        $this->assertEquals(true, $subKey->canSign());
        $this->assertEquals(false, $subKey->canEncrypt());
        //$this->assertEquals(true, $subKey->hasPrivate());
        $this->assertEquals(false, $subKey->isRevoked());
        $this->assertEquals(false, $subKey->isDisabled());
    }

    public function testDeletePublicKey()
    {
        global $resource_1;
        global $resource_2;

        $resource_1->deletePublicKey(TEST2_ID);
        $resource_2->deletePublicKey(TEST1_ID);
    }

    public function testDeletePrivateKey()
    {
        global $resource_1;
        global $resource_2;
        
        //print_r($resource_1->getKeys());
        //$resource_1->deletePrivateKey(TEST1_ID);
        //print_r($resource_1->getKeys());
        
        //$resource_2->deletePrivateKey(TEST2_ID);
    }
}
