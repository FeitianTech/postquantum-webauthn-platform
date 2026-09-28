import { Button } from './Button';

// Back to where the page or dialog came from: "Back" with an arrow, what it
// returns to in its title ("Return to authenticator list").
export function BackButton({ onBack, title }: { onBack: () => void; title: string }) {
  return (
    <Button variant="secondary" size="sm" title={title} onClick={onBack} icon={<span aria-hidden="true">←</span>}>
      Back
    </Button>
  );
}
