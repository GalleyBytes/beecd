import { AlertCircle, CheckCircle, Info, XCircle } from 'lucide-react';

type AlertType = 'success' | 'error' | 'warning' | 'info';

interface AlertProps {
    type: AlertType;
    title?: string;
    message: string;
    onDismiss?: () => void;
}

const alertStyles: Record<AlertType, { bg: string; border: string; text: string; icon: typeof CheckCircle }> = {
    success: {
        bg: 'bg-green-50 dark:bg-green-900/20',
        border: 'border-green-400 dark:border-green-600',
        text: 'text-green-800 dark:text-green-300',
        icon: CheckCircle,
    },
    error: {
        bg: 'bg-red-50 dark:bg-red-900/20',
        border: 'border-red-400 dark:border-red-600',
        text: 'text-red-800 dark:text-red-300',
        icon: XCircle,
    },
    warning: {
        bg: 'bg-yellow-50 dark:bg-yellow-900/20',
        border: 'border-yellow-400 dark:border-yellow-600',
        text: 'text-yellow-800 dark:text-yellow-300',
        icon: AlertCircle,
    },
    info: {
        bg: 'bg-blue-50 dark:bg-blue-900/20',
        border: 'border-blue-400 dark:border-blue-600',
        text: 'text-blue-800 dark:text-blue-300',
        icon: Info,
    },
};

export function Alert({ type, title, message, onDismiss }: AlertProps) {
    const styles = alertStyles[type];
    const Icon = styles.icon;

    return (
        <div className={`rounded-md p-4 ${styles.bg} border-l-4 ${styles.border}`}>
            <div className="flex">
                <div className="flex-shrink-0">
                    <Icon className={`h-5 w-5 ${styles.text}`} />
                </div>
                <div className="ml-3 flex-1">
                    {title && <h3 className={`text-sm font-medium ${styles.text}`}>{title}</h3>}
                    <p className={`text-sm ${styles.text} ${title ? 'mt-1' : ''}`}>{message}</p>
                </div>
                {onDismiss && (
                    <div className="ml-auto pl-3">
                        <button
                            onClick={onDismiss}
                            className={`inline-flex rounded-md p-1.5 ${styles.bg} ${styles.text} hover:opacity-75 focus:outline-none`}
                        >
                            <XCircle className="h-5 w-5" />
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}
