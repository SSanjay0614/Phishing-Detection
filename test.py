# quick_test.py - Simple test script to verify everything works

from page_phishing import WebpagePhishingDetector
import json

def test_detector():
    print("🚀 Starting Webpage Phishing Detector Test...")
    
    # Initialize detector
    detector = WebpagePhishingDetector()
    
    # Test websites (start with safe ones)
    test_sites = [
        "https://example.com",
        "https://httpbin.org/forms/post",  # Has forms for testing
        "https://google.com"
    ]
    
    print(f"Testing {len(test_sites)} websites...\n")
    
    for i, url in enumerate(test_sites, 1):
        print(f"{'='*50}")
        print(f"Test {i}/{len(test_sites)}: {url}")
        print(f"{'='*50}")
        
        try:
            # Run detection
            result = detector.detect_webpage_phishing(url)
            
            # Display results
            print(f"✅ Analysis Complete!")
            print(f"🔍 Is Phishing: {'YES' if result['is_phishing'] else 'NO'}")
            print(f"📊 Confidence: {result['confidence']:.1f}%")
            print(f"⚠️  Risk Score: {result['combined_risk_score']:.3f}/1.0")
            
            # Show key findings
            features = result['webpage_features']
            print(f"\n📋 Key Findings:")
            print(f"   - Forms found: {features['forms_count']}")
            print(f"   - Suspicious keywords: {len(features['suspicious_keywords'])}")
            print(f"   - Social engineering signals: {len(features['social_engineering_signals'])}")
            print(f"   - Popup indicators: {features['popup_indicators']}")
            print(f"   - Suspicious elements: {len(features['suspicious_elements'])}")
            
            # Show LLM analysis
            llm = result['llm_analysis']
            print(f"\n🤖 AI Analysis:")
            print(f"   - Phishing likelihood: {llm['phishing_likelihood']}/100")
            print(f"   - Main red flags: {', '.join(llm['content_red_flags'][:3])}")
            
            # Show risk factors if any
            if result['content_analysis']['risk_factors']:
                print(f"\n⚠️  Risk Factors:")
                for factor, score in result['content_analysis']['risk_factors'].items():
                    print(f"   - {factor}: {score:.3f}")
            
        except Exception as e:
            print(f"❌ Error analyzing {url}: {e}")
        
        print(f"\n" + "="*50 + "\n")
    
    print("✨ Test completed!")
    print("\n💡 Tips:")
    print("   - Try testing suspicious-looking websites")
    print("   - Check sites with login forms")
    print("   - Test sites with urgent language")

if __name__ == "__main__":
    test_detector()