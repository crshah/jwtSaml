var axios = require('axios');

module.exports = class UserInfo {
    constructor(userInfoEndpoint) {
        this._userInfoEndpoint = userInfoEndpoint;
    }

    verifyAccessToken(bearerToken) {
        
        return new Promise( (resolve, reject) => {
            var config = {
                method: 'get',
                url: this._userInfoEndpoint,
                headers: { 
                    'Accept': 'application/json', 
                    'Authorization': 'Bearer '+bearerToken
                }
            }
            axios(config).then( (response) => {
                var jwt = {
                    claims: {sub: response.data.preferred_username}
                }
                resolve(jwt);
            }).catch((e)=> {
                reject(e);
            });
        })
    }

}

