class Tokenization_WD(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)

    def _process(self, data):
        article = data
        article_tagged = self.tag_article(article["text"])
        article_word_def = self.wordnet_definitions(article_tagged)
        return (article_word_def, article)

    def tag_article(self, article):
        sents = nltk.sent_tokenize(article)
        sentence = []
        for sent in sents:
            tokens = nltk.word_tokenize(sent)
            tag_tuples = nltk.pos_tag(tokens)
            for string, tag in tag_tuples:
                token = {"word": string, "pos": tag}
                sentence.append(token)
        return sentence

    def wordnet_definitions(self, sentence):
        wnl = nltk.WordNetLemmatizer()
        for token in sentence:
            word = token["word"]
            wn_pos = wordnet_pos_code(token["pos"])
            if self.is_punctuation(word):
                token["punct"] = True
            elif self.is_stopword(word):
                pass
            elif len(wordnet.synsets(word, wn_pos)) > 0:
                token["wn_lemma"] = wnl.lemmatize(word.lower())
                token["wn_pos"] = self.wordnet_pos_label(token["pos"])
                defs = [sense.definition() for sense in wordnet.synsets(word, wn_pos)]
                token["wn_def"] = "; \n".join(defs)
            else:
                pass
        return sentence

    def wordnet_pos_label(self, tag):
        if tag.startswith("NN"):
            return "Noun"
        elif tag.startswith("VB"):
            return "Verb"
        elif tag.startswith("JJ"):
            return "Adjective"
        elif tag.startswith("RB"):
            return "Adverb"
        else:
            return tag

    def is_stopword(self, string):
        return string.lower() in nltk.corpus.stopwords.words("english")

    def is_punctuation(self, string):
        for char in string:
            if char.isalpha() or char.isdigit():
                return False
        return True
