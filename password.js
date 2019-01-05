var crypto = require('crypto');
//
// Password Utility Function Module. 
// Contains helper functions for creating password salts and 
// verifying user passwords against stored hashes. 
// 

function genRandomString(length)
{
    return crypto.randomBytes(Math.ceil(length/2))
               .toString('hex')
               .slice(0,length);
};

function sha512(password, salt)
{
    var hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    var value = hash.digest('hex');
    return { salt:salt, hash:value};
}

module.exports = {
    saltHashPassword: 
    function(userpassword)
    {
        var salt = genRandomString(16);  // salt length is 16 bytes
        var passwordData = sha512(userpassword, salt);
        return passwordData;
    },
    checkUserPassword:  
    function(salt, hash, password)
    {
        var passwordData = sha512(password, salt);
        var passed = false;
        if (passwordData.hash === hash)
        {
            passed = true;
        }
        return passed;
    }
};


