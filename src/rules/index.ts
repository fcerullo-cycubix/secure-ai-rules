import { Rule } from '../components/SecureAIDirectory';
import angularSecurity from './angular-security';
import rubySecurity from './ruby-security';
import pythonSecurity from './python-security';
import nodejsSecurity from './nodejs-security';
import javaSecurity from './java-security';
import dotnetSecurity from './dotnet-security';

const allRules = [
  angularSecurity,
  rubySecurity,
  pythonSecurity,
  nodejsSecurity,
  javaSecurity,
  dotnetSecurity,
];

// Validate and ensure all rules have required fields
export const rules: Rule[] = allRules.filter((rule): rule is Rule => {
  const isValid = rule && 
    typeof rule.id === 'string' &&
    typeof rule.title === 'string' &&
    typeof rule.summary === 'string' &&
    typeof rule.body === 'string' &&
    Array.isArray(rule.tags) &&
    rule.tags.every(tag => typeof tag === 'string');
    
  if (!isValid) {
    console.warn('Invalid rule found:', rule?.id || 'unknown rule');
  }
  
  return isValid;
});