const saml = require('samlify');
var fs = require('fs');
var config = require('./config');

// Custom template
const loginResponseTemplate = {
  context: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}">
                <saml:Issuer>{Issuer}</saml:Issuer>
                <samlp:Status>
                     <samlp:StatusCode Value="{StatusCode}"/>
                </samlp:Status>
                <saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                     <saml:Issuer>{Issuer}</saml:Issuer>
                     <saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID>
                          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                              <saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}"/>
                          </saml:SubjectConfirmation>
                     </saml:Subject>
                     
                     <saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}">
                          <saml:AudienceRestriction>
                               <saml:Audience>{Audience}</saml:Audience>
                          </saml:AudienceRestriction>
                     </saml:Conditions>
                     <saml:AuthnStatement AuthnInstant="{IssueInstant}" SessionNotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" SessionIndex="{IssueInstant}">
                      <saml:AuthnContext>
                        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                      </saml:AuthnContext>
                     </saml:AuthnStatement>
                     {AttributeStatement}
                </saml:Assertion>
           </samlp:Response>`,
  attributes: [
    { name: "mail", valueTag: "user.email", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" }
  ],
};

const idp = new saml.IdentityProvider({
  // required
  metadata: fs.readFileSync(config.idp.metadata),
  privateKey: fs.readFileSync(config.idp.privateKey),
  loginResponseTemplate: loginResponseTemplate,
  isAssertionEncrypted: false
});

const sp = new saml.ServiceProvider({
  metadata: fs.readFileSync(config.sp.metadata),
  transformationAlgorithms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
  ]
  
});

const sampleRequestInfo = { extract: { request: { id: '' } } };

const createTemplateCallback = (_idp, _sp, user) => template => {
  const _id =  _idp.entitySetting.generateID();
  const now = new Date();
  const spEntityID = _sp.entityMeta.getEntityID();
  console.log(spEntityID);
  const idpSetting = _idp.entitySetting;
  const fiveMinutesLater = new Date(now.getTime());
  fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
  //console.log(JSON.stringify(_sp.entityMeta));
  const acl = _sp.entityMeta.getAssertionConsumerService('post');
  console.log(acl);
  const tvalue = {
    ID: _id,
    AssertionID: idpSetting.generateID ? idpSetting.generateID() : `${uuid.v4()}`,
    Destination: _sp.entityMeta.getAssertionConsumerService('post'),
    Audience: spEntityID,
    SubjectRecipient: acl,
    NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    NameID: user.email,
    Issuer: idp.entityMeta.getEntityID(),
    IssueInstant: now.toISOString(),
    ConditionsNotBefore: now.toISOString(),
    ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
    AssertionConsumerServiceURL: _sp.entityMeta.getAssertionConsumerService('post'),
    EntityID: spEntityID,
   // InResponseTo: '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4',
    StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    attrUserEmail: user.email,
    //attrUserName: 'mynameinsp',
  };
  return {
    id: _id,
    context: saml.SamlLib.replaceTagsByValue(template, tvalue),
  };
};

module.exports = {
  idp: idp,
  sp: sp,
  createTemplateCallback: createTemplateCallback
}