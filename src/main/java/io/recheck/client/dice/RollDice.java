package io.recheck.client.dice;

public class RollDice {
    public static void main(String[] args) {
        phrase();
    }

    public static String phrase() {
        String hand, match, trimmed, passphrase;
        int hands = 12; // passphrase words length
        StringBuilder passBuilder = new StringBuilder();

        for (int j = 0; j < hands; j++) {
            StringBuilder handBuilder = new StringBuilder();

            for (int i = 0; i < 5; i++) {  // get five dice
                Dice throwDie = new Dice();
                handBuilder.append(throwDie.roll());
            }
            hand = handBuilder.toString(); // all five dice

            ScanFile sf = new ScanFile();
            match = sf.getWord(hand);
            trimmed = match.replace(hand, "").trim();
            passBuilder.append(trimmed).append(" ");
        }
        passphrase = passBuilder.toString();

        return passphrase.trim();
    }
}