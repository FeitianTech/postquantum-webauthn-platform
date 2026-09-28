// The Advanced tab's form and JSON editor in the component tests: both over one
// request, with the providers the section has, and the saved credentials kept.
import { screen } from '@testing-library/react';

import { AuthenticationForm } from '@/components/advanced/AuthenticationForm';
import { JsonEditor } from '@/components/advanced/JsonEditor';
import { RegistrationForm } from '@/components/advanced/RegistrationForm';
import { useAdvancedRequest } from '@/components/advanced/useAdvancedRequest';
import { useAuthenticationRequest } from '@/components/advanced/useAuthenticationRequest';
import { SavedCredentialsProvider } from '@/components/credentials/useSavedCredentials';
import { ToastProvider } from '@/components/ui/Toast';

import { keepRecords, warmUpRoutes } from './credentials';
import { stubFetch } from './fetch';
import { renderPage } from './page';

function Harness() {
  const request = useAdvancedRequest();
  return (
    <>
      <button type="button" onClick={request.resetForm}>
        Reset the form
      </button>
      <RegistrationForm request={request} />
      <JsonEditor scope="registration" request={request} />
    </>
  );
}

export function renderForm(records: object[] = []) {
  keepRecords(records);
  stubFetch(warmUpRoutes());
  renderPage(
    <ToastProvider>
      <SavedCredentialsProvider>
        <Harness />
      </SavedCredentialsProvider>
    </ToastProvider>,
  );
}

export const editor = () => screen.getByRole('textbox', { name: 'JSON Editor (CredentialCreationOptions)' }) as HTMLTextAreaElement;
export const publicKey = () => JSON.parse(editor().value).publicKey;

// The authentication's form and JSON editor over one request, with what the
// registration form decides of Allow Credentials (its hints and attachment).
function AuthenticationHarness() {
  const registration = useAdvancedRequest();
  const request = useAuthenticationRequest({ hints: registration.settings.hints, attachment: registration.settings.attachment });
  return (
    <>
      <button type="button" onClick={request.resetForm}>
        Reset the authentication
      </button>
      <button type="button" onClick={() => registration.change('hints', ['client-device'])}>
        Registration hint client-device
      </button>
      <button type="button" onClick={() => registration.change('algorithms', [])}>
        Registration without algorithms
      </button>
      <output data-registration-algorithms="">{registration.settings.algorithms.join(',')}</output>
      <AuthenticationForm request={request} />
      <JsonEditor scope="authentication" request={request} />
    </>
  );
}

export function renderAuthenticationForm(records: object[] = []) {
  keepRecords(records);
  stubFetch(warmUpRoutes());
  renderPage(
    <ToastProvider>
      <SavedCredentialsProvider>
        <AuthenticationHarness />
      </SavedCredentialsProvider>
    </ToastProvider>,
  );
}

export const authEditor = () => screen.getByRole('textbox', { name: 'JSON Editor (CredentialRequestOptions)' }) as HTMLTextAreaElement;
export const authPublicKey = () => JSON.parse(authEditor().value).publicKey;
