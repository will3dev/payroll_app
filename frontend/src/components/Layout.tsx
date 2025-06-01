import React from 'react';

interface LayoutProps {
    children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({children}) => {
    return (
        <div className="flex flex-col min-h-screen bg-gray-100">
            {/*Navigation Header */}
            <nav className="bg-white shadow-sm border-b">
                <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between h-16">
                        <div className="flex items-center">
                            <h1 className="text-xl font-bold text-gray-900">PayrollApp</h1>
                        </div>
                        <div className="flex items-center space-x-4">
                            <button className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                                Connect Wallet
                            </button>
                        </div>
                    </div>
                </div>
            </nav>

            {/*Main Content */}
            <main className="flex-1">
                <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                    {children}
                </div>
            </main>
            
        </div>
    )
}

export default Layout;