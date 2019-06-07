const assert = require('assert');
const should = require('should');

const { validateDomain } = require('../spfParse');

describe('validateDomain' , () => {
    it('should return true or false', () => {
        let out = validateDomain('https://spark-public.s3.amazonaws.com/dataanalysis/loansData.csv')
        console.log(typeof out);
        should(out).is.true();
    });
});
