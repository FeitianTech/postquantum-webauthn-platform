// The Advanced tab's form and JSON editor in the component tests: both over one
// request, with the providers the section has, and the saved credentials kept.
import { screen } from '@testing-library/react';

import { JsonEditor } from '@/components/advanced/JsonEditor';
import { RegistrationForm } from '@/components/advanced/RegistrationForm';
import { useAdvancedRequest } from '@/components/advanced/useAdvancedRequest';
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
